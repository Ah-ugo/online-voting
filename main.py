from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from typing import List, Optional, Dict, Any, Annotated
from datetime import datetime, timedelta, timezone
from bson import ObjectId
from pymongo import MongoClient, DESCENDING
import motor.motor_asyncio
import cloudinary
import cloudinary.uploader
import os
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from pydantic import BaseModel, Field, EmailStr, validator, BeforeValidator, field_validator
import json
from fastapi.responses import JSONResponse

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Student Election API")

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure Cloudinary
cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("API_KEY"),
    api_secret=os.getenv("API_SECRET")
)

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URL", "mongodb://localhost:27017")
client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = client.student_election_db

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# Helper for ObjectId validation
def validate_object_id(v):
    if v is None:
        return None
    if not ObjectId.is_valid(v):
        return v  # Return as is if not valid, will be handled later
    return str(v)


PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]


# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user_by_matric(matric_number: str):
    user = await db.users.find_one({"matricNumber": matric_number})
    return user


async def authenticate_user(matric_number: str, password: str):
    user = await get_user_by_matric(matric_number)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        matric_number: str = payload.get("sub")
        if matric_number is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    user = await get_user_by_matric(matric_number)
    if user is None:
        raise credentials_exception
    return user


async def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    return current_user


# Models
class UserBase(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    matricNumber: str
    department: Optional[str] = None
    faculty: Optional[str] = None


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[EmailStr] = None
    department: Optional[str] = None
    faculty: Optional[str] = None
    role: Optional[str] = None


class UserInDB(UserBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    role: str = "student"
    profileImageUrl: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class Token(BaseModel):
    access_token: str
    token_type: str
    user: dict


class FacultyBase(BaseModel):
    name: str


class FacultyInDB(FacultyBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class DepartmentBase(BaseModel):
    name: str
    faculty: str


class DepartmentInDB(DepartmentBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


# class ElectionBase(BaseModel):
#     title: str
#     description: str
#     category: str  # SUG, Faculty, Department
#     startDate: datetime
#     endDate: datetime
#
#     @field_validator("startDate", "endDate", mode="before")
#     @classmethod
#     def make_timezone_aware(cls, v):
#         if isinstance(v, str):
#             v = datetime.fromisoformat(v)
#         if v.tzinfo is None:
#             return v.replace(tzinfo=timezone.utc)
#         return v.astimezone(timezone.utc)

class ElectionBase(BaseModel):
    title: str
    description: str
    category: str  # SUG, Faculty, Department
    startDate: datetime
    endDate: datetime
    facultyId: Optional[str] = None  # Only required for Faculty elections
    departmentId: Optional[str] = None  # Only required for Department elections

    @field_validator("startDate", "endDate", mode="before")
    @classmethod
    def make_timezone_aware(cls, v):
        if isinstance(v, str):
            v = datetime.fromisoformat(v)
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("facultyId", "departmentId")
    @classmethod
    def validate_ids(cls, v, info):
        if v is not None and not ObjectId.is_valid(v):
            raise ValueError(f"Invalid {info.field_name}")
        return v


class ElectionInDB(ElectionBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    status: str = "upcoming"  # upcoming, active, completed
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class CandidateBase(BaseModel):
    firstName: str
    lastName: str
    email: EmailStr
    matricNumber: str
    position: str
    manifesto: str
    electionId: str


class CandidateInDB(CandidateBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    profileImageUrl: Optional[str] = None
    createdAt: datetime = Field(default_factory=datetime.utcnow)
    updatedAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class VoteBase(BaseModel):
    electionId: str
    candidateId: str


class VoteInDB(VoteBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    userId: str
    createdAt: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


# Routes
@app.get("/")
async def root():
    return {"message": "Welcome to the Student Election API"}


# Auth routes
@app.post("/auth/register", response_description="Register a new user")
async def register(
        firstName: str = Form(...),
        lastName: str = Form(...),
        email: EmailStr = Form(...),
        matricNumber: str = Form(...),
        password: str = Form(...),
        department: Optional[str] = Form(None),
        faculty: Optional[str] = Form(None),
        profileImage: Optional[UploadFile] = File(None)
):
    # Check if user already exists
    existing_user = await db.users.find_one({"matricNumber": matricNumber})
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this matric number already exists"
        )

    # Upload profile image if provided
    profile_image_url = None
    if profileImage:
        upload_result = cloudinary.uploader.upload(profileImage.file)
        profile_image_url = upload_result.get("secure_url")

    # Create new user
    user = {
        "firstName": firstName,
        "lastName": lastName,
        "email": email,
        "matricNumber": matricNumber,
        "password": get_password_hash(password),
        "department": department,
        "faculty": faculty,
        "role": "student",
        "profileImageUrl": profile_image_url,
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow()
    }

    new_user = await db.users.insert_one(user)

    return {"id": str(new_user.inserted_id), "message": "User registered successfully"}


@app.post("/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect matric number or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Populate faculty and department info
    if user.get("faculty") and isinstance(user["faculty"], str):
        try:
            if ObjectId.is_valid(user["faculty"]):
                faculty = await db.faculties.find_one({"_id": ObjectId(user["faculty"])})
                if faculty:
                    user["faculty"] = {"_id": str(faculty["_id"]), "name": faculty["name"]}
        except Exception as e:
            # If there's an error, just keep the faculty as is
            pass

    if user.get("department") and isinstance(user["department"], str):
        try:
            if ObjectId.is_valid(user["department"]):
                department = await db.departments.find_one({"_id": ObjectId(user["department"])})
                if department:
                    user["department"] = {"_id": str(department["_id"]), "name": department["name"]}
        except Exception as e:
            # If there's an error, just keep the department as is
            pass

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["matricNumber"]}, expires_delta=access_token_expires
    )

    # Remove password from user data
    user.pop("password", None)
    user["_id"] = str(user["_id"])

    return {"access_token": access_token, "token_type": "bearer", "user": user}


@app.get("/auth/me", response_description="Get current user")
async def get_me(current_user: dict = Depends(get_current_user)):
    # Populate faculty and department info
    if current_user.get("faculty") and isinstance(current_user["faculty"], str):
        try:
            if ObjectId.is_valid(current_user["faculty"]):
                faculty_id = ObjectId(current_user["faculty"])
                faculty = await db.faculties.find_one({"_id": faculty_id})
                if faculty:
                    current_user["faculty"] = {"_id": str(faculty["_id"]), "name": faculty["name"]}
        except Exception as e:
            # If there's an error, just keep the faculty as is
            pass

    if current_user.get("department") and isinstance(current_user["department"], str):
        try:
            if ObjectId.is_valid(current_user["department"]):
                department_id = ObjectId(current_user["department"])
                department = await db.departments.find_one({"_id": department_id})
                if department:
                    current_user["department"] = {"_id": str(department["_id"]), "name": department["name"]}
        except Exception as e:
            # If there's an error, just keep the department as is
            pass

    # Remove password from user data
    current_user.pop("password", None)
    current_user["_id"] = str(current_user["_id"])

    return current_user


# User routes
@app.get("/admin/users", response_description="List all users")
async def list_users(current_user: dict = Depends(get_admin_user)):
    users = await db.users.find().to_list(1000)

    # Process users
    for user in users:
        user["_id"] = str(user["_id"])
        user.pop("password", None)

        # Populate faculty and department info
        if user.get("faculty") and isinstance(user["faculty"], str):
            try:
                if ObjectId.is_valid(user["faculty"]):
                    faculty_id = ObjectId(user["faculty"])
                    faculty = await db.faculties.find_one({"_id": faculty_id})
                    if faculty:
                        user["faculty"] = {"_id": str(faculty["_id"]), "name": faculty["name"]}
            except Exception as e:
                # If there's an error, just keep the faculty as is
                pass

        if user.get("department") and isinstance(user["department"], str):
            try:
                if ObjectId.is_valid(user["department"]):
                    department_id = ObjectId(user["department"])
                    department = await db.departments.find_one({"_id": department_id})
                    if department:
                        user["department"] = {"_id": str(department["_id"]), "name": department["name"]}
            except Exception as e:
                # If there's an error, just keep the department as is
                pass

    return users


@app.put("/admin/users/{user_id}", response_description="Update a user")
async def update_user(user_id: str, user_update: UserUpdate, current_user: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")
        user_obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    update_data = {k: v for k, v in user_update.dict().items() if v is not None}
    update_data["updatedAt"] = datetime.utcnow()

    update_result = await db.users.update_one(
        {"_id": user_obj_id},
        {"$set": update_data}
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    updated_user = await db.users.find_one({"_id": user_obj_id})
    updated_user["_id"] = str(updated_user["_id"])
    updated_user.pop("password", None)

    return updated_user


@app.delete("/admin/users/{user_id}", response_description="Delete a user")
async def delete_user(user_id: str, current_user: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(user_id):
            raise HTTPException(status_code=400, detail="Invalid user ID")
        user_obj_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    delete_result = await db.users.delete_one({"_id": user_obj_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    # Delete all votes by this user
    await db.votes.delete_many({"userId": user_id})

    return {"message": "User deleted successfully"}


# Faculty routes
@app.get("/faculties", response_description="List all faculties")
async def list_faculties():
    faculties = await db.faculties.find().to_list(1000)

    # Count departments for each faculty
    for faculty in faculties:
        faculty["_id"] = str(faculty["_id"])
        department_count = await db.departments.count_documents({"faculty": str(faculty["_id"])})
        faculty["departmentCount"] = department_count

    return faculties


@app.post("/admin/faculties", response_description="Create a new faculty")
async def create_faculty(faculty: FacultyBase, current_user: dict = Depends(get_admin_user)):
    new_faculty = await db.faculties.insert_one(
        {
            **faculty.dict(),
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
    )
    created_faculty = await db.faculties.find_one({"_id": new_faculty.inserted_id})
    created_faculty["_id"] = str(created_faculty["_id"])
    return created_faculty


@app.put("/admin/faculties/{faculty_id}", response_description="Update a faculty")
async def update_faculty(faculty_id: str, faculty: FacultyBase, current_user: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(faculty_id):
            raise HTTPException(status_code=400, detail="Invalid faculty ID")
        faculty_obj_id = ObjectId(faculty_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid faculty ID")

    update_result = await db.faculties.update_one(
        {"_id": faculty_obj_id},
        {"$set": {**faculty.dict(), "updatedAt": datetime.utcnow()}}
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Faculty not found")

    updated_faculty = await db.faculties.find_one({"_id": faculty_obj_id})
    updated_faculty["_id"] = str(updated_faculty["_id"])
    return updated_faculty


@app.delete("/admin/faculties/{faculty_id}", response_description="Delete a faculty")
async def delete_faculty(faculty_id: str, current_user: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(faculty_id):
            raise HTTPException(status_code=400, detail="Invalid faculty ID")
        faculty_obj_id = ObjectId(faculty_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid faculty ID")

    # Delete all departments in this faculty
    await db.departments.delete_many({"faculty": faculty_id})

    delete_result = await db.faculties.delete_one({"_id": faculty_obj_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Faculty not found")

    return {"message": "Faculty and its departments deleted successfully"}


# Department routes
@app.get("/departments", response_description="List departments")
async def list_departments(faculty: Optional[str] = None):
    query = {}
    if faculty:
        query["faculty"] = faculty

    departments = await db.departments.find(query).to_list(1000)

    # Populate faculty info
    for department in departments:
        department["_id"] = str(department["_id"])
        if department.get("faculty") and isinstance(department["faculty"], str):
            try:
                if ObjectId.is_valid(department["faculty"]):
                    faculty_id = ObjectId(department["faculty"])
                    faculty = await db.faculties.find_one({"_id": faculty_id})
                    if faculty:
                        department["faculty"] = {"_id": str(faculty["_id"]), "name": faculty["name"]}
            except Exception:
                # If there's an error, just keep the faculty as is
                pass

    return departments


@app.post("/admin/departments", response_description="Create a new department")
async def create_department(department: DepartmentBase, current_user: dict = Depends(get_admin_user)):
    # Verify faculty exists
    try:
        if not ObjectId.is_valid(department.faculty):
            raise HTTPException(status_code=400, detail="Invalid faculty ID")
        faculty_id = ObjectId(department.faculty)
        faculty = await db.faculties.find_one({"_id": faculty_id})
        if not faculty:
            raise HTTPException(status_code=404, detail="Faculty not found")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid faculty ID")

    new_department = await db.departments.insert_one(
        {
            **department.dict(),
            "createdAt": datetime.utcnow(),
            "updatedAt": datetime.utcnow()
        }
    )
    created_department = await db.departments.find_one({"_id": new_department.inserted_id})
    created_department["_id"] = str(created_department["_id"])
    return created_department


@app.put("/admin/departments/{department_id}", response_description="Update a department")
async def update_department(department_id: str, department: DepartmentBase,
                            current_user: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(department_id):
            raise HTTPException(status_code=400, detail="Invalid department ID")
        department_obj_id = ObjectId(department_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid department ID")

    # Verify faculty exists
    try:
        if not ObjectId.is_valid(department.faculty):
            raise HTTPException(status_code=400, detail="Invalid faculty ID")
        faculty_id = ObjectId(department.faculty)
        faculty = await db.faculties.find_one({"_id": faculty_id})
        if not faculty:
            raise HTTPException(status_code=404, detail="Faculty not found")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid faculty ID")

    update_result = await db.departments.update_one(
        {"_id": department_obj_id},
        {"$set": {**department.dict(), "updatedAt": datetime.utcnow()}}
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Department not found")

    updated_department = await db.departments.find_one({"_id": department_obj_id})
    updated_department["_id"] = str(updated_department["_id"])
    return updated_department


@app.delete("/admin/departments/{department_id}", response_description="Delete a department")
async def delete_department(department_id: str, current_user: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(department_id):
            raise HTTPException(status_code=400, detail="Invalid department ID")
        department_obj_id = ObjectId(department_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid department ID")

    delete_result = await db.departments.delete_one({"_id": department_obj_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Department not found")

    return {"message": "Department deleted successfully"}


# Election routes
@app.get("/elections/active", response_description="List active elections")
async def list_active_elections(current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are currently active
    query = {
        "startDate": {"$lte": now},
        "endDate": {"$gte": now}
    }

    # Get user's faculty and department IDs
    user_faculty_id = None
    user_department_id = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
    elif current_user.get("faculty"):
        user_faculty_id = current_user["faculty"]

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
    elif current_user.get("department"):
        user_department_id = current_user["department"]

    elections = await db.elections.find(query).to_list(1000)

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])

        # SUG elections are available to all students
        if election["category"] == "SUG":
            filtered_elections.append(election)
        # Faculty elections are only available to students in that faculty
        elif election["category"] == "Faculty" and user_faculty_id:
            # Check if user's faculty matches the election's faculty restriction
            if not election.get("facultyId") or str(election.get("facultyId")) == str(user_faculty_id):
                filtered_elections.append(election)
        # Department elections are only available to students in that department
        elif election["category"] == "Department" and user_department_id:
            # Check if user's department matches the election's department restriction
            if not election.get("departmentId") or str(election.get("departmentId")) == str(user_department_id):
                filtered_elections.append(election)

    return filtered_elections


@app.get("/elections/upcoming", response_description="List upcoming elections")
async def list_upcoming_elections(current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are upcoming
    query = {
        "startDate": {"$gt": now}
    }

    # Get user's faculty and department IDs
    user_faculty_id = None
    user_department_id = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
    elif current_user.get("faculty"):
        user_faculty_id = current_user["faculty"]

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
    elif current_user.get("department"):
        user_department_id = current_user["department"]

    elections = await db.elections.find(query).to_list(1000)

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])

        # SUG elections are available to all students
        if election["category"] == "SUG":
            filtered_elections.append(election)
        # Faculty elections are only available to students in that faculty
        elif election["category"] == "Faculty" and user_faculty_id:
            # Check if user's faculty matches the election's faculty restriction
            if not election.get("facultyId") or str(election.get("facultyId")) == str(user_faculty_id):
                filtered_elections.append(election)
        # Department elections are only available to students in that department
        elif election["category"] == "Department" and user_department_id:
            # Check if user's department matches the election's department restriction
            if not election.get("departmentId") or str(election.get("departmentId")) == str(user_department_id):
                filtered_elections.append(election)

    return filtered_elections


@app.get("/elections/past", response_description="List past elections")
async def list_past_elections(current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are completed
    query = {
        "endDate": {"$lt": now}
    }

    # Get user's faculty and department IDs
    user_faculty_id = None
    user_department_id = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
    elif current_user.get("faculty"):
        user_faculty_id = current_user["faculty"]

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
    elif current_user.get("department"):
        user_department_id = current_user["department"]

    elections = await db.elections.find(query).to_list(1000)

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])

        # SUG elections are available to all students
        if election["category"] == "SUG":
            filtered_elections.append(election)
        # Faculty elections are only available to students in that faculty
        elif election["category"] == "Faculty" and user_faculty_id:
            # Check if user's faculty matches the election's faculty restriction
            if not election.get("facultyId") or str(election.get("facultyId")) == str(user_faculty_id):
                filtered_elections.append(election)
        # Department elections are only available to students in that department
        elif election["category"] == "Department" and user_department_id:
            # Check if user's department matches the election's department restriction
            if not election.get("departmentId") or str(election.get("departmentId")) == str(user_department_id):
                filtered_elections.append(election)

    return filtered_elections


@app.get("/elections/completed", response_description="List completed elections")
async def list_completed_elections(current_user: dict = Depends(get_current_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are completed
    query = {
        "endDate": {"$lt": now}
    }

    # Get user's faculty and department IDs
    user_faculty_id = None
    user_department_id = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
    elif current_user.get("faculty"):
        user_faculty_id = current_user["faculty"]

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
    elif current_user.get("department"):
        user_department_id = current_user["department"]

    elections = await db.elections.find(query).to_list(1000)

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])

        # SUG elections are available to all students
        if election["category"] == "SUG":
            filtered_elections.append(election)
        # Faculty elections are only available to students in that faculty
        elif election["category"] == "Faculty" and user_faculty_id:
            # Check if user's faculty matches the election's faculty restriction
            if not election.get("facultyId") or str(election.get("facultyId")) == str(user_faculty_id):
                filtered_elections.append(election)
        # Department elections are only available to students in that department
        elif election["category"] == "Department" and user_department_id:
            # Check if user's department matches the election's department restriction
            if not election.get("departmentId") or str(election.get("departmentId")) == str(user_department_id):
                filtered_elections.append(election)

    return filtered_elections


@app.get("/elections/{election_id}", response_description="Get election details")
async def get_election(election_id: str, current_user: dict = Depends(get_current_user)):
    election_obj_id = validate_object_id(election_id, "Invalid election ID")

    election = await db.elections.find_one({"_id": election_obj_id})

    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    # Check if user has access to this election
    user_faculty_id = None
    user_department_id = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
    elif current_user.get("faculty"):
        user_faculty_id = current_user["faculty"]

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
    elif current_user.get("department"):
        user_department_id = current_user["department"]

    # SUG elections are accessible to all
    if election["category"] == "SUG":
        pass
    # Faculty elections are only accessible to students in that faculty
    elif election["category"] == "Faculty" and election.get("facultyId"):
        if not user_faculty_id or str(election["facultyId"]) != str(user_faculty_id):
            raise HTTPException(status_code=403, detail="You don't have access to this election")
    # Department elections are only accessible to students in that department
    elif election["category"] == "Department" and election.get("departmentId"):
        if not user_department_id or str(election["departmentId"]) != str(user_department_id):
            raise HTTPException(status_code=403, detail="You don't have access to this election")

    election["_id"] = str(election["_id"])
    return election


@app.get("/elections/{election_id}/results", response_description="Get election results")
async def get_election_results(election_id: str, current_user: dict = Depends(get_current_user)):
    election_obj_id = validate_object_id(election_id, "Invalid election ID")

    election = await db.elections.find_one({"_id": election_obj_id})

    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    # Check if election is completed
    now = datetime.now(timezone.utc)
    if election["endDate"] > now:
        raise HTTPException(status_code=400, detail="Election is not yet completed")

    # Get all candidates for this election
    candidates = await db.candidates.find({"electionId": election_id}).to_list(1000)

    results = []
    for candidate in candidates:
        # Count votes for this candidate
        vote_count = await db.votes.count_documents({"candidateId": str(candidate["_id"])})

        results.append({
            "candidate": {
                "_id": str(candidate["_id"]),
                "firstName": candidate["firstName"],
                "lastName": candidate["lastName"],
                "position": candidate["position"],
                "profileImageUrl": candidate.get("profileImageUrl")
            },
            "voteCount": vote_count
        })

    # Sort results by vote count in descending order
    results.sort(key=lambda x: x["voteCount"], reverse=True)

    return results


@app.post("/admin/elections", response_description="Create a new election")
async def create_election(election: ElectionBase, current_user: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)

    # Validate that facultyId is provided for Faculty elections
    if election.category == "Faculty" and not election.facultyId:
        raise HTTPException(status_code=400, detail="Faculty ID is required for Faculty elections")

    # Validate that departmentId is provided for Department elections
    if election.category == "Department" and not election.departmentId:
        raise HTTPException(status_code=400, detail="Department ID is required for Department elections")

    # Verify faculty exists if facultyId is provided
    if election.facultyId:
        try:
            faculty_id = validate_object_id(election.facultyId, "Invalid faculty ID")
            faculty = await db.faculties.find_one({"_id": faculty_id})
            if not faculty:
                raise HTTPException(status_code=404, detail="Faculty not found")
        except HTTPException:
            raise HTTPException(status_code=400, detail="Invalid faculty ID")

    # Verify department exists if departmentId is provided
    if election.departmentId:
        try:
            department_id = validate_object_id(election.departmentId, "Invalid department ID")
            department = await db.departments.find_one({"_id": department_id})
            if not department:
                raise HTTPException(status_code=404, detail="Department not found")
        except HTTPException:
            raise HTTPException(status_code=400, detail="Invalid department ID")

    # Determine initial status based on dates
    status = "upcoming"
    if election.startDate <= now <= election.endDate:
        status = "active"
    elif election.endDate < now:
        status = "completed"

    new_election = await db.elections.insert_one(
        {
            **election.dict(),
            "status": status,
            "createdAt": datetime.now(timezone.utc),
            "updatedAt": datetime.now(timezone.utc)
        }
    )
    created_election = await db.elections.find_one({"_id": new_election.inserted_id})
    created_election["_id"] = str(created_election["_id"])
    return created_election


@app.put("/admin/elections/{election_id}", response_description="Update an election")
async def update_election(election_id: str, election: ElectionBase, current_user: dict = Depends(get_admin_user)):
    election_obj_id = validate_object_id(election_id, "Invalid election ID")

    # Validate that facultyId is provided for Faculty elections
    if election.category == "Faculty" and not election.facultyId:
        raise HTTPException(status_code=400, detail="Faculty ID is required for Faculty elections")

    # Validate that departmentId is provided for Department elections
    if election.category == "Department" and not election.departmentId:
        raise HTTPException(status_code=400, detail="Department ID is required for Department elections")

    # Verify faculty exists if facultyId is provided
    if election.facultyId:
        try:
            faculty_id = validate_object_id(election.facultyId, "Invalid faculty ID")
            faculty = await db.faculties.find_one({"_id": faculty_id})
            if not faculty:
                raise HTTPException(status_code=404, detail="Faculty not found")
        except HTTPException:
            raise HTTPException(status_code=400, detail="Invalid faculty ID")

    # Verify department exists if departmentId is provided
    if election.departmentId:
        try:
            department_id = validate_object_id(election.departmentId, "Invalid department ID")
            department = await db.departments.find_one({"_id": department_id})
            if not department:
                raise HTTPException(status_code=404, detail="Department not found")
        except HTTPException:
            raise HTTPException(status_code=400, detail="Invalid department ID")

    # Determine status based on dates
    now = datetime.now(timezone.utc)
    status = "upcoming"
    if election.startDate <= now <= election.endDate:
        status = "active"
    elif election.endDate < now:
        status = "completed"

    update_result = await db.elections.update_one(
        {"_id": election_obj_id},
        {"$set": {
            **election.dict(),
            "status": status,
            "updatedAt": datetime.now(timezone.utc)
        }}
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Election not found")

    updated_election = await db.elections.find_one({"_id": election_obj_id})
    updated_election["_id"] = str(updated_election["_id"])
    return updated_election


# Admin election routes
@app.get("/admin/elections/active", response_description="List all active elections for admin")
async def admin_list_active_elections(current_user: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are currently active
    query = {
        "startDate": {"$lte": now},
        "endDate": {"$gte": now}
    }

    elections = await db.elections.find(query).to_list(1000)

    for election in elections:
        election["_id"] = str(election["_id"])

    return elections


@app.get("/admin/elections/upcoming", response_description="List all upcoming elections for admin")
async def admin_list_upcoming_elections(current_user: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are upcoming
    query = {
        "startDate": {"$gt": now}
    }

    elections = await db.elections.find(query).to_list(1000)

    for election in elections:
        election["_id"] = str(election["_id"])

    return elections


@app.get("/admin/elections/completed", response_description="List all completed elections for admin")
async def admin_list_completed_elections(current_user: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are completed
    query = {
        "endDate": {"$lt": now}
    }

    elections = await db.elections.find(query).to_list(1000)

    for election in elections:
        election["_id"] = str(election["_id"])

    return elections


@app.get("/admin/elections/active-upcoming", response_description="List all active and upcoming elections for admin")
async def admin_list_active_upcoming_elections(current_user: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)

    # Get elections that are active or upcoming
    query = {
        "endDate": {"$gte": now}
    }

    elections = await db.elections.find(query).to_list(1000)

    for election in elections:
        election["_id"] = str(election["_id"])

    return elections


@app.delete("/admin/elections/{election_id}", response_description="Delete an election")
async def delete_election(election_id: str, current_user: dict = Depends(get_admin_user)):
    election_obj_id = validate_object_id(election_id, "Invalid election ID")

    # Delete all candidates for this election
    await db.candidates.delete_many({"electionId": election_id})

    # Delete all votes for this election
    await db.votes.delete_many({"electionId": election_id})

    delete_result = await db.elections.delete_one({"_id": election_obj_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Election not found")

    return {"message": "Election and related data deleted successfully"}


# Candidate routes
# @app.get("/elections/{election_id}/candidates", response_description="List candidates for an election")
# async def list_candidates(election_id: str, current_user: dict = Depends(get_current_user)):
#     try:
#         if not ObjectId.is_valid(election_id):
#             raise HTTPException(status_code=400, detail="Invalid election ID")
#         election_obj_id = ObjectId(election_id)
#     except Exception:
#         raise HTTPException(status_code=400, detail="Invalid election ID")
#
#     # Verify election exists
#     election = await db.elections.find_one({"_id": election_obj_id})
#     if not election:
#         raise HTTPException(status_code=404, detail="Election not found")
#
#     candidates = await db.candidates.find({"electionId": election_id}).to_list(1000)
#
#     # Process candidates
#     for candidate in candidates:
#         candidate["_id"] = str(candidate["_id"])
#
#     return candidates

@app.get("/candidates/election/{election_id}", response_description="List candidates for an election")
async def list_election_candidates(election_id: str, current_user: dict = Depends(get_current_user)):
    # Verify election exists and user has access
    election_obj_id = validate_object_id(election_id, "Invalid election ID")

    election = await db.elections.find_one({"_id": election_obj_id})
    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    # Get candidates for this election
    candidates = await db.candidates.find({"electionId": election_id}).to_list(1000)

    for candidate in candidates:
        candidate["_id"] = str(candidate["_id"])

    return candidates


@app.post("/admin/candidates", response_description="Create a new candidate")
async def create_candidate(
        firstName: str = Form(...),
        lastName: str = Form(...),
        email: EmailStr = Form(...),
        matricNumber: str = Form(...),
        position: str = Form(...),
        manifesto: str = Form(...),
        electionId: str = Form(...),
        profileImage: Optional[UploadFile] = File(None),
        current_user: dict = Depends(get_admin_user)
):
    # Verify election exists
    election_obj_id = validate_object_id(electionId, "Invalid election ID")
    election = await db.elections.find_one({"_id": election_obj_id})
    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    # Upload profile image if provided
    profile_image_url = None
    if profileImage:
        upload_result = cloudinary.uploader.upload(profileImage.file)
        profile_image_url = upload_result.get("secure_url")

    # Create new candidate
    candidate = {
        "firstName": firstName,
        "lastName": lastName,
        "email": email,
        "matricNumber": matricNumber,
        "position": position,
        "manifesto": manifesto,
        "electionId": electionId,
        "profileImageUrl": profile_image_url,
        "createdAt": datetime.now(timezone.utc),
        "updatedAt": datetime.now(timezone.utc)
    }

    new_candidate = await db.candidates.insert_one(candidate)

    created_candidate = await db.candidates.find_one({"_id": new_candidate.inserted_id})
    created_candidate["_id"] = str(created_candidate["_id"])

    return created_candidate


@app.put("/admin/candidates/{candidate_id}", response_description="Update a candidate")
async def update_candidate(
        candidate_id: str,
        firstName: Optional[str] = Form(None),
        lastName: Optional[str] = Form(None),
        email: Optional[EmailStr] = Form(None),
        matricNumber: Optional[str] = Form(None),
        position: Optional[str] = Form(None),
        manifesto: Optional[str] = Form(None),
        electionId: Optional[str] = Form(None),
        profileImage: Optional[UploadFile] = File(None),
        current_user: dict = Depends(get_admin_user)
):
    try:
        if not ObjectId.is_valid(candidate_id):
            raise HTTPException(status_code=400, detail="Invalid candidate ID")
        candidate_obj_id = ObjectId(candidate_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid candidate ID")

    # Get existing candidate
    candidate = await db.candidates.find_one({"_id": candidate_obj_id})
    if not candidate:
        raise HTTPException(status_code=404, detail="Candidate not found")

    # Verify election exists if provided
    if electionId:
        try:
            if not ObjectId.is_valid(electionId):
                raise HTTPException(status_code=400, detail="Invalid election ID")
            election_obj_id = ObjectId(electionId)
            election = await db.elections.find_one({"_id": election_obj_id})
            if not election:
                raise HTTPException(status_code=404, detail="Election not found")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid election ID")

    # Upload profile image if provided
    profile_image_url = candidate.get("profileImageUrl")
    if profileImage:
        upload_result = cloudinary.uploader.upload(profileImage.file)
        profile_image_url = upload_result.get("secure_url")

    # Update candidate
    update_data = {}
    if firstName:
        update_data["firstName"] = firstName
    if lastName:
        update_data["lastName"] = lastName
    if email:
        update_data["email"] = email
    if matricNumber:
        update_data["matricNumber"] = matricNumber
    if position:
        update_data["position"] = position
    if manifesto:
        update_data["manifesto"] = manifesto
    if electionId:
        update_data["electionId"] = electionId
    if profile_image_url:
        update_data["profileImageUrl"] = profile_image_url

    update_data["updatedAt"] = datetime.utcnow()

    update_result = await db.candidates.update_one(
        {"_id": candidate_obj_id},
        {"$set": update_data}
    )

    updated_candidate = await db.candidates.find_one({"_id": candidate_obj_id})
    updated_candidate["_id"] = str(updated_candidate["_id"])

    return updated_candidate


@app.delete("/admin/candidates/{candidate_id}", response_description="Delete a candidate")
async def delete_candidate(candidate_id: str, current_user: dict = Depends(get_admin_user)):
    try:
        if not ObjectId.is_valid(candidate_id):
            raise HTTPException(status_code=400, detail="Invalid candidate ID")
        candidate_obj_id = ObjectId(candidate_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid candidate ID")

    # Delete all votes for this candidate
    await db.votes.delete_many({"candidateId": candidate_id})

    delete_result = await db.candidates.delete_one({"_id": candidate_obj_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Candidate not found")

    return {"message": "Candidate deleted successfully"}


# Voting routes
@app.post("/vote", response_description="Cast a vote")
async def cast_vote(vote: VoteBase, current_user: dict = Depends(get_current_user)):
    # Verify election exists and is active
    try:
        if not ObjectId.is_valid(vote.electionId):
            raise HTTPException(status_code=400, detail="Invalid election ID")
        election_obj_id = ObjectId(vote.electionId)
        now = datetime.utcnow()
        election = await db.elections.find_one({
            "_id": election_obj_id,
            "startDate": {"$lte": now},
            "endDate": {"$gte": now}
        })
        if not election:
            raise HTTPException(status_code=404, detail="Election not found or not active")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid election ID")

    # Verify candidate exists and belongs to the election
    try:
        if not ObjectId.is_valid(vote.candidateId):
            raise HTTPException(status_code=400, detail="Invalid candidate ID")
        candidate_obj_id = ObjectId(vote.candidateId)
        candidate = await db.candidates.find_one({
            "_id": candidate_obj_id,
            "electionId": vote.electionId
        })
        if not candidate:
            raise HTTPException(status_code=404, detail="Candidate not found or not part of this election")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid candidate ID")

    # Check if user has already voted for this position in this election
    user_id = str(current_user["_id"])
    existing_vote = await db.votes.find_one({
        "userId": user_id,
        "electionId": vote.electionId,
        "position": candidate["position"]
    })

    if existing_vote:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"You have already voted for {candidate['position']} in this election"
        )

    # Cast vote
    new_vote = await db.votes.insert_one({
        "userId": user_id,
        "electionId": vote.electionId,
        "candidateId": vote.candidateId,
        "position": candidate["position"],
        "createdAt": datetime.utcnow()
    })

    return {"message": "Vote cast successfully", "id": str(new_vote.inserted_id)}


@app.get("/user/votes", response_description="Get user's votes")
async def get_user_votes(current_user: dict = Depends(get_current_user)):
    user_id = str(current_user["_id"])
    votes = await db.votes.find({"userId": user_id}).to_list(1000)

    # Process votes
    result = []
    for vote in votes:
        vote["_id"] = str(vote["_id"])

        # Get election info
        try:
            election_id = vote["electionId"]
            if ObjectId.is_valid(election_id):
                election = await db.elections.find_one({"_id": ObjectId(election_id)})
                if election:
                    vote["election"] = {
                        "_id": str(election["_id"]),
                        "title": election["title"]
                    }
        except Exception:
            pass

        # Get candidate info
        try:
            candidate_id = vote["candidateId"]
            if ObjectId.is_valid(candidate_id):
                candidate = await db.candidates.find_one({"_id": ObjectId(candidate_id)})
                if candidate:
                    vote["candidate"] = {
                        "_id": str(candidate["_id"]),
                        "firstName": candidate["firstName"],
                        "lastName": candidate["lastName"],
                        "position": candidate["position"]
                    }
        except Exception:
            pass

        result.append(vote)

    return result


# Admin dashboard routes
@app.get("/admin/dashboard", response_description="Get admin dashboard data")
async def get_admin_dashboard(current_user: dict = Depends(get_admin_user)):
    # Count total users
    total_users = await db.users.count_documents({})

    # Count total elections
    total_elections = await db.elections.count_documents({})

    # Count active elections
    now = datetime.utcnow()
    active_elections = await db.elections.count_documents({
        "startDate": {"$lte": now},
        "endDate": {"$gte": now}
    })

    # Count total votes
    total_votes = await db.votes.count_documents({})

    # Get recent elections
    recent_elections = await db.elections.find().sort("createdAt", DESCENDING).limit(5).to_list(5)
    for election in recent_elections:
        election["_id"] = str(election["_id"])

    # Get recent users
    recent_users = await db.users.find().sort("createdAt", DESCENDING).limit(5).to_list(5)
    for user in recent_users:
        user["_id"] = str(user["_id"])
        user.pop("password", None)

    return {
        "totalUsers": total_users,
        "totalElections": total_elections,
        "activeElections": active_elections,
        "totalVotes": total_votes,
        "recentElections": recent_elections,
        "recentUsers": recent_users
    }


