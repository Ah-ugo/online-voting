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


class ElectionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    startDate: Optional[datetime] = None
    endDate: Optional[datetime] = None
    facultyId: Optional[str] = None
    departmentId: Optional[str] = None


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
    position: str  # Added position field to track which position the vote is for
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
@app.put("/users/profile", response_description="Update user profile")
async def update_profile(
        firstName: Optional[str] = Form(None),
        lastName: Optional[str] = Form(None),
        email: Optional[EmailStr] = Form(None),
        department: Optional[str] = Form(None),
        faculty: Optional[str] = Form(None),
        profileImage: Optional[UploadFile] = File(None),
        current_user: dict = Depends(get_current_user)
):
    user_id = current_user["_id"]

    try:
        if isinstance(user_id, str):
            user_id = ObjectId(user_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    # Prepare update data
    update_data = {}
    if firstName is not None:
        update_data["firstName"] = firstName
    if lastName is not None:
        update_data["lastName"] = lastName
    if email is not None:
        update_data["email"] = email
    if department is not None:
        update_data["department"] = department
    if faculty is not None:
        update_data["faculty"] = faculty

    # Upload profile image if provided
    if profileImage:
        upload_result = cloudinary.uploader.upload(profileImage.file)
        profile_image_url = upload_result.get("secure_url")
        update_data["profileImageUrl"] = profile_image_url

    update_data["updatedAt"] = datetime.utcnow()

    # Update user
    update_result = await db.users.update_one(
        {"_id": user_id},
        {"$set": update_data}
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    # Get updated user
    updated_user = await db.users.find_one({"_id": user_id})

    # Populate faculty and department info
    if updated_user.get("faculty") and isinstance(updated_user["faculty"], str):
        try:
            if ObjectId.is_valid(updated_user["faculty"]):
                faculty = await db.faculties.find_one({"_id": ObjectId(updated_user["faculty"])})
                if faculty:
                    updated_user["faculty"] = {"_id": str(faculty["_id"]), "name": faculty["name"]}
        except Exception:
            pass

    if updated_user.get("department") and isinstance(updated_user["department"], str):
        try:
            if ObjectId.is_valid(updated_user["department"]):
                department = await db.departments.find_one({"_id": ObjectId(updated_user["department"])})
                if department:
                    updated_user["department"] = {"_id": str(department["_id"]), "name": department["name"]}
        except Exception:
            pass

    # Remove password from user data
    updated_user.pop("password", None)
    updated_user["_id"] = str(updated_user["_id"])

    return updated_user


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
@app.get("/elections/active", response_description="List active elections", response_model=List[dict])
async def list_active_elections(current_user: dict = Depends(get_current_user)):
    now_utc = datetime.now(timezone.utc)
    print(f"Current UTC time for user elections: {now_utc}")
    print(f"Current User object: {current_user}")

    pipeline = [
        {
            "$match": {
                "$expr": {
                    "$and": [
                        {"$lte": [{"$toDate": "$startDate"}, now_utc]},
                        {"$gte": [{"$toDate": "$endDate"}, now_utc]}
                    ]
                }
            }
        }
    ]

    elections = await db.elections.aggregate(pipeline).to_list(1000)
    print(f"Total number of active elections found: {len(elections)}")

    # Get user's faculty and department info
    user_faculty_id = None
    user_faculty_name = None
    user_department_id = None
    user_department_name = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
        user_faculty_name = current_user["faculty"].get("name")
    elif current_user.get("faculty"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["faculty"]):
            user_faculty_id = current_user["faculty"]
            # Try to get the name
            faculty = await db.faculties.find_one({"_id": ObjectId(current_user["faculty"])})
            if faculty:
                user_faculty_name = faculty.get("name")
        else:
            # Assume it's a name
            user_faculty_name = current_user["faculty"]
            # Try to get the ID
            faculty = await db.faculties.find_one({"name": user_faculty_name})
            if faculty:
                user_faculty_id = str(faculty["_id"])

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
        user_department_name = current_user["department"].get("name")
    elif current_user.get("department"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["department"]):
            user_department_id = current_user["department"]
            # Try to get the name
            department = await db.departments.find_one({"_id": ObjectId(current_user["department"])})
            if department:
                user_department_name = department.get("name")
        else:
            # Assume it's a name
            user_department_name = current_user["department"]
            # Try to get the ID
            department = await db.departments.find_one({"name": user_department_name})
            if department:
                user_department_id = str(department["_id"])

    print(f"User faculty ID: {user_faculty_id}, User faculty Name: {user_faculty_name}")
    print(f"User department ID: {user_department_id}, User department Name: {user_department_name}")

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])
        category = election.get("category", "").lower()

        print(f"Processing election: {election.get('title')} with category: {category}")

        if category == "sug":
            print(f"  Adding SUG election: {election.get('title')}")
            filtered_elections.append(election)
        elif category == "faculty":
            print(f"  Checking faculty election: {election.get('title')}")
            election_faculty_id = election.get("facultyId")

            if election_faculty_id and user_faculty_id:
                # Check if IDs match
                if str(election_faculty_id) == str(user_faculty_id):
                    print(f"  Faculty ID match, adding election")
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                        if faculty and user_faculty_name and faculty.get("name").lower() == user_faculty_name.lower():
                            print(f"  Faculty name match, adding election")
                            filtered_elections.append(election)
                        else:
                            print(f"  Faculty mismatch, skipping")
                    except Exception as e:
                        print(f"  Error checking faculty: {e}")
            elif election_faculty_id and user_faculty_name:
                # Try to match by name
                try:
                    faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                    if faculty and faculty.get("name").lower() == user_faculty_name.lower():
                        print(f"  Faculty name match, adding election")
                        filtered_elections.append(election)
                    else:
                        print(f"  Faculty name mismatch, skipping")
                except Exception as e:
                    print(f"  Error checking faculty: {e}")
            elif not election_faculty_id:
                # No faculty restriction
                print(f"  No faculty restriction, adding election")
                filtered_elections.append(election)
            else:
                print(f"  User has no faculty, skipping")
        elif category == "department":
            print(f"  Checking department election: {election.get('title')}")
            election_department_id = election.get("departmentId")

            if election_department_id and user_department_id:
                # Check if IDs match
                if str(election_department_id) == str(user_department_id):
                    print(f"  Department ID match, adding election")
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                        if department and user_department_name and department.get(
                                "name").lower() == user_department_name.lower():
                            print(f"  Department name match, adding election")
                            filtered_elections.append(election)
                        else:
                            print(f"  Department mismatch, skipping")
                    except Exception as e:
                        print(f"  Error checking department: {e}")
            elif election_department_id and user_department_name:
                # Try to match by name
                try:
                    department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                    if department and department.get("name").lower() == user_department_name.lower():
                        print(f"  Department name match, adding election")
                        filtered_elections.append(election)
                    else:
                        print(f"  Department name mismatch, skipping")
                except Exception as e:
                    print(f"  Error checking department: {e}")
            elif not election_department_id:
                # No department restriction
                print(f"  No department restriction, adding election")
                filtered_elections.append(election)
            else:
                print(f"  User has no department, skipping")
        else:
            print(f"  Unrecognized category: {category}, adding")
            filtered_elections.append(election)

    print(f"Number of filtered active elections for user: {len(filtered_elections)}")
    return filtered_elections


@app.get("/elections/upcoming", response_description="List upcoming elections")
async def list_upcoming_elections(current_user: dict = Depends(get_current_user)):
    now_utc = datetime.now(timezone.utc)
    print(f"Current UTC time for upcoming elections: {now_utc}")

    # MongoDB query using proper BSON date format for comparison
    pipeline = [
        {
            "$match": {
                "$expr": {
                    "$gt": [{"$toDate": "$startDate"}, now_utc]
                }
            }
        }
    ]

    elections = await db.elections.aggregate(pipeline).to_list(1000)
    print(f"Total number of upcoming elections found: {len(elections)}")

    # Get user's faculty and department info
    user_faculty_id = None
    user_faculty_name = None
    user_department_id = None
    user_department_name = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
        user_faculty_name = current_user["faculty"].get("name")
    elif current_user.get("faculty"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["faculty"]):
            user_faculty_id = current_user["faculty"]
            # Try to get the name
            faculty = await db.faculties.find_one({"_id": ObjectId(current_user["faculty"])})
            if faculty:
                user_faculty_name = faculty.get("name")
        else:
            # Assume it's a name
            user_faculty_name = current_user["faculty"]
            # Try to get the ID
            faculty = await db.faculties.find_one({"name": user_faculty_name})
            if faculty:
                user_faculty_id = str(faculty["_id"])

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
        user_department_name = current_user["department"].get("name")
    elif current_user.get("department"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["department"]):
            user_department_id = current_user["department"]
            # Try to get the name
            department = await db.departments.find_one({"_id": ObjectId(current_user["department"])})
            if department:
                user_department_name = department.get("name")
        else:
            # Assume it's a name
            user_department_name = current_user["department"]
            # Try to get the ID
            department = await db.departments.find_one({"name": user_department_name})
            if department:
                user_department_id = str(department["_id"])

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])
        category = election.get("category", "").lower()

        if category == "sug":
            filtered_elections.append(election)
        elif category == "faculty":
            election_faculty_id = election.get("facultyId")

            if election_faculty_id and user_faculty_id:
                # Check if IDs match
                if str(election_faculty_id) == str(user_faculty_id):
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                        if faculty and user_faculty_name and faculty.get("name").lower() == user_faculty_name.lower():
                            filtered_elections.append(election)
                    except Exception:
                        pass
            elif election_faculty_id and user_faculty_name:
                # Try to match by name
                try:
                    faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                    if faculty and faculty.get("name").lower() == user_faculty_name.lower():
                        filtered_elections.append(election)
                except Exception:
                    pass
            elif not election_faculty_id:
                # No faculty restriction
                filtered_elections.append(election)
        elif category == "department":
            election_department_id = election.get("departmentId")

            if election_department_id and user_department_id:
                # Check if IDs match
                if str(election_department_id) == str(user_department_id):
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                        if department and user_department_name and department.get(
                                "name").lower() == user_department_name.lower():
                            filtered_elections.append(election)
                    except Exception:
                        pass
            elif election_department_id and user_department_name:
                # Try to match by name
                try:
                    department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                    if department and department.get("name").lower() == user_department_name.lower():
                        filtered_elections.append(election)
                except Exception:
                    pass
            elif not election_department_id:
                # No department restriction
                filtered_elections.append(election)
        else:
            filtered_elections.append(election)

    print(f"Number of filtered upcoming elections for user: {len(filtered_elections)}")
    return filtered_elections


@app.get("/elections/past", response_description="List past elections")
async def list_past_elections(current_user: dict = Depends(get_current_user)):
    now_utc = datetime.now(timezone.utc)
    print(f"Current UTC time for past elections: {now_utc}")

    # MongoDB query using proper BSON date format for comparison
    pipeline = [
        {
            "$match": {
                "$expr": {
                    "$lt": [{"$toDate": "$endDate"}, now_utc]
                }
            }
        }
    ]

    elections = await db.elections.aggregate(pipeline).to_list(1000)
    print(f"Total number of past elections found: {len(elections)}")

    # Get user's faculty and department info
    user_faculty_id = None
    user_faculty_name = None
    user_department_id = None
    user_department_name = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
        user_faculty_name = current_user["faculty"].get("name")
    elif current_user.get("faculty"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["faculty"]):
            user_faculty_id = current_user["faculty"]
            # Try to get the name
            faculty = await db.faculties.find_one({"_id": ObjectId(current_user["faculty"])})
            if faculty:
                user_faculty_name = faculty.get("name")
        else:
            # Assume it's a name
            user_faculty_name = current_user["faculty"]
            # Try to get the ID
            faculty = await db.faculties.find_one({"name": user_faculty_name})
            if faculty:
                user_faculty_id = str(faculty["_id"])

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
        user_department_name = current_user["department"].get("name")
    elif current_user.get("department"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["department"]):
            user_department_id = current_user["department"]
            # Try to get the name
            department = await db.departments.find_one({"_id": ObjectId(current_user["department"])})
            if department:
                user_department_name = department.get("name")
        else:
            # Assume it's a name
            user_department_name = current_user["department"]
            # Try to get the ID
            department = await db.departments.find_one({"name": user_department_name})
            if department:
                user_department_id = str(department["_id"])

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])
        category = election.get("category", "").lower()

        if category == "sug":
            filtered_elections.append(election)
        elif category == "faculty":
            election_faculty_id = election.get("facultyId")

            if election_faculty_id and user_faculty_id:
                # Check if IDs match
                if str(election_faculty_id) == str(user_faculty_id):
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                        if faculty and user_faculty_name and faculty.get("name").lower() == user_faculty_name.lower():
                            filtered_elections.append(election)
                    except Exception:
                        pass
            elif election_faculty_id and user_faculty_name:
                # Try to match by name
                try:
                    faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                    if faculty and faculty.get("name").lower() == user_faculty_name.lower():
                        filtered_elections.append(election)
                except Exception:
                    pass
            elif not election_faculty_id:
                # No faculty restriction
                filtered_elections.append(election)
        elif category == "department":
            election_department_id = election.get("departmentId")

            if election_department_id and user_department_id:
                # Check if IDs match
                if str(election_department_id) == str(user_department_id):
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                        if department and user_department_name and department.get(
                                "name").lower() == user_department_name.lower():
                            filtered_elections.append(election)
                    except Exception:
                        pass
            elif election_department_id and user_department_name:
                # Try to match by name
                try:
                    department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                    if department and department.get("name").lower() == user_department_name.lower():
                        filtered_elections.append(election)
                except Exception:
                    pass
            elif not election_department_id:
                # No department restriction
                filtered_elections.append(election)
        else:
            filtered_elections.append(election)

    print(f"Number of filtered past elections for user: {len(filtered_elections)}")
    return filtered_elections


@app.get("/elections/completed", response_description="List completed elections")
async def list_completed_elections(current_user: dict = Depends(get_current_user)):
    # This is essentially the same as past elections, so we're using the same implementation
    now_utc = datetime.now(timezone.utc)
    print(f"Current UTC time for completed elections: {now_utc}")

    # MongoDB query using proper BSON date format for comparison
    pipeline = [
        {
            "$match": {
                "$expr": {
                    "$lt": [{"$toDate": "$endDate"}, now_utc]
                }
            }
        }
    ]

    elections = await db.elections.aggregate(pipeline).to_list(1000)
    print(f"Total number of completed elections found: {len(elections)}")

    # Get user's faculty and department info
    user_faculty_id = None
    user_faculty_name = None
    user_department_id = None
    user_department_name = None

    if isinstance(current_user.get("faculty"), dict):
        user_faculty_id = current_user["faculty"].get("_id")
        user_faculty_name = current_user["faculty"].get("name")
    elif current_user.get("faculty"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["faculty"]):
            user_faculty_id = current_user["faculty"]
            # Try to get the name
            faculty = await db.faculties.find_one({"_id": ObjectId(current_user["faculty"])})
            if faculty:
                user_faculty_name = faculty.get("name")
        else:
            # Assume it's a name
            user_faculty_name = current_user["faculty"]
            # Try to get the ID
            faculty = await db.faculties.find_one({"name": user_faculty_name})
            if faculty:
                user_faculty_id = str(faculty["_id"])

    if isinstance(current_user.get("department"), dict):
        user_department_id = current_user["department"].get("_id")
        user_department_name = current_user["department"].get("name")
    elif current_user.get("department"):
        # Check if it's an ObjectId or a name
        if ObjectId.is_valid(current_user["department"]):
            user_department_id = current_user["department"]
            # Try to get the name
            department = await db.departments.find_one({"_id": ObjectId(current_user["department"])})
            if department:
                user_department_name = department.get("name")
        else:
            # Assume it's a name
            user_department_name = current_user["department"]
            # Try to get the ID
            department = await db.departments.find_one({"name": user_department_name})
            if department:
                user_department_id = str(department["_id"])

    # Filter elections based on user's faculty/department
    filtered_elections = []
    for election in elections:
        election["_id"] = str(election["_id"])
        category = election.get("category", "").lower()

        if category == "sug":
            filtered_elections.append(election)
        elif category == "faculty":
            election_faculty_id = election.get("facultyId")

            if election_faculty_id and user_faculty_id:
                # Check if IDs match
                if str(election_faculty_id) == str(user_faculty_id):
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                        if faculty and user_faculty_name and faculty.get("name").lower() == user_faculty_name.lower():
                            filtered_elections.append(election)
                    except Exception:
                        pass
            elif election_faculty_id and user_faculty_name:
                # Try to match by name
                try:
                    faculty = await db.faculties.find_one({"_id": ObjectId(election_faculty_id)})
                    if faculty and faculty.get("name").lower() == user_faculty_name.lower():
                        filtered_elections.append(election)
                except Exception:
                    pass
            elif not election_faculty_id:
                # No faculty restriction
                filtered_elections.append(election)
        elif category == "department":
            election_department_id = election.get("departmentId")

            if election_department_id and user_department_id:
                # Check if IDs match
                if str(election_department_id) == str(user_department_id):
                    filtered_elections.append(election)
                else:
                    # Try to match by name
                    try:
                        department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                        if department and user_department_name and department.get(
                                "name").lower() == user_department_name.lower():
                            filtered_elections.append(election)
                    except Exception:
                        pass
            elif election_department_id and user_department_name:
                # Try to match by name
                try:
                    department = await db.departments.find_one({"_id": ObjectId(election_department_id)})
                    if department and department.get("name").lower() == user_department_name.lower():
                        filtered_elections.append(election)
                except Exception:
                    pass
            elif not election_department_id:
                # No department restriction
                filtered_elections.append(election)
        else:
            filtered_elections.append(election)

    print(f"Number of filtered completed elections for user: {len(filtered_elections)}")
    return filtered_elections


@app.get("/elections/{election_id}", response_description="Get election details")
async def get_election(election_id: str, current_user: dict = Depends(get_current_user)):
    # Debug: Print the ID we're looking for
    print(f"Looking for election with ID: {election_id}")

    # Important: Convert string ID to ObjectId properly
    try:
        if not ObjectId.is_valid(election_id):
            raise HTTPException(status_code=400, detail="Invalid election ID format")
        election_obj_id = ObjectId(election_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid election ID: {str(e)}")

    # Debug: Check if the collection exists and has data
    count = await db.elections.count_documents({})
    print(f"Total elections in database: {count}")

    # Try to find the election using the ObjectId
    election = await db.elections.find_one({"_id": election_obj_id})

    if not election:
        # If not found, try a direct string comparison as fallback
        # This is not ideal but can help diagnose issues
        election = await db.elections.find_one({"_id": election_id})
        if not election:
            raise HTTPException(status_code=404, detail="Election not found")

    # Convert ObjectId to string for JSON serialization
    election["_id"] = str(election["_id"])

    return election


@app.get("/candidates/election/{election_id}", response_description="List candidates for an election")
async def list_election_candidates(election_id: str, current_user: dict = Depends(get_current_user)):
    """
    Lists candidates for a specific election.
    """
    # Debug: Print the ID we're looking for
    print(f"Looking for election with ID: {election_id}")

    # Important: Convert string ID to ObjectId properly
    try:
        if not ObjectId.is_valid(election_id):
            raise HTTPException(status_code=400, detail="Invalid election ID format")
        election_obj_id = ObjectId(election_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid election ID: {str(e)}")

    # Debug: Check if the election exists
    election = await db.elections.find_one({"_id": election_obj_id})
    if not election:
        # Debug: Print all elections to help diagnose the issue
        all_elections = await db.elections.find().to_list(10)
        print(f"Election not found. Available elections (first 10):")
        for e in all_elections:
            print(f"  ID: {e['_id']}, Title: {e.get('title')}")

        raise HTTPException(status_code=404, detail="Election not found")

    print(f"Found election: {election.get('title')}")

    # Get candidates for this election
    candidates = await db.candidates.find({"electionId": election_id}).to_list(1000)
    print(f"Found {len(candidates)} candidates for this election")

    for candidate in candidates:
        candidate["_id"] = str(candidate["_id"])

    return candidates


@app.post("/votes", response_description="Cast a vote")
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


@app.get("/votes/check/{election_id}", response_description="Check if user has voted in an election")
async def check_vote(election_id: str, current_user: dict = Depends(get_current_user)):
    # Verify election exists
    try:
        if not ObjectId.is_valid(election_id):
            raise HTTPException(status_code=400, detail="Invalid election ID")
        election_obj_id = ObjectId(election_id)
        election = await db.elections.find_one({"_id": election_obj_id})
        if not election:
            raise HTTPException(status_code=404, detail="Election not found")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid election ID")

    # Get all positions in this election
    candidates = await db.candidates.find({"electionId": election_id}).to_list(1000)
    positions = set(candidate["position"] for candidate in candidates)

    # Check which positions the user has voted for
    user_id = str(current_user["_id"])
    votes = await db.votes.find({
        "userId": user_id,
        "electionId": election_id
    }).to_list(1000)

    voted_positions = set(vote["position"] for vote in votes)

    # Return information about which positions have been voted for
    return {
        "hasVoted": len(votes) > 0,
        "votedPositions": list(voted_positions),
        "availablePositions": list(positions),
        "remainingPositions": list(positions - voted_positions)
    }


@app.get("/votes/history", response_description="Get user's voting history")
async def get_voting_history(current_user: dict = Depends(get_current_user)):
    votes = await db.votes.find({"userId": str(current_user["_id"])}).to_list(1000)

    # Populate election and candidate info for each vote
    for vote in votes:
        vote["_id"] = str(vote["_id"])

        if vote.get("electionId"):
            try:
                election_id = vote["electionId"]
                election = await db.elections.find_one({"_id": ObjectId(election_id)})
                if election:
                    vote["election"] = {
                        "_id": str(election["_id"]),
                        "title": election["title"],
                        "category": election["category"]
                    }
            except Exception:
                # Keep the electionId as is if it's invalid
                pass

        if vote.get("candidateId"):
            try:
                candidate_id = vote["candidateId"]
                candidate = await db.candidates.find_one({"_id": ObjectId(candidate_id)})
                if candidate:
                    vote["candidate"] = {
                        "_id": str(candidate["_id"]),
                        "firstName": candidate["firstName"],
                        "lastName": candidate["lastName"],
                        "position": candidate["position"]
                    }
            except Exception:
                # Keep the candidateId as is if it's invalid
                pass

    return votes


@app.get("/elections/{election_id}/results", response_description="Get election results")
async def get_election_results(election_id: str, current_user: dict = Depends(get_current_user)):
    try:
        election_obj_id = ObjectId(election_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid election ID")

    election = await db.elections.find_one({"_id": election_obj_id})

    if not election:
        raise HTTPException(status_code=404, detail="Election not found")

    # Check if election is completed
    now = datetime.utcnow()
    if election["endDate"] > now:
        raise HTTPException(status_code=400, detail="Election is not yet completed")

    # Get all candidates for this election
    candidates = await db.candidates.find({"electionId": election_id}).to_list(1000)

    # Group candidates by position
    candidates_by_position = {}
    for candidate in candidates:
        position = candidate["position"]
        if position not in candidates_by_position:
            candidates_by_position[position] = []
        candidates_by_position[position].append(candidate)

    # Get results for each position
    results_by_position = {}
    for position, position_candidates in candidates_by_position.items():
        position_results = []
        for candidate in position_candidates:
            # Count votes for this candidate
            vote_count = await db.votes.count_documents({
                "candidateId": str(candidate["_id"]),
                "position": position
            })

            position_results.append({
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
        position_results.sort(key=lambda x: x["voteCount"], reverse=True)
        results_by_position[position] = position_results

    return {
        "election": {
            "_id": str(election["_id"]),
            "title": election["title"],
            "category": election["category"]
        },
        "resultsByPosition": results_by_position
    }


# Admin routes
@app.get("/admin/elections", response_description="List all elections for admin")
async def admin_list_elections(current_user: dict = Depends(get_admin_user)):
    elections = await db.elections.find().to_list(1000)
    for election in elections:
        election["_id"] = str(election["_id"])
    return elections


@app.get("/admin/elections/active-upcoming", response_description="List active and upcoming elections for admin")
async def admin_list_active_upcoming_elections(current_user: dict = Depends(get_admin_user)):
    now = datetime.utcnow()
    elections = await db.elections.find({
        "endDate": {"$gte": now}
    }).to_list(1000)

    for election in elections:
        election["_id"] = str(election["_id"])

    return elections


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
            faculty_id = validate_object_id(election.facultyId)
            if faculty_id is None:
                raise HTTPException(status_code=400, detail="Invalid faculty ID")
            faculty = await db.faculties.find_one({"_id": ObjectId(faculty_id)})
            if not faculty:
                raise HTTPException(status_code=404, detail="Faculty not found")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid faculty ID")

    # Verify department exists if departmentId is provided
    if election.departmentId:
        try:
            department_id = validate_object_id(election.departmentId)
            if department_id is None:
                raise HTTPException(status_code=400, detail="Invalid department ID")
            department = await db.departments.find_one({"_id": ObjectId(department_id)})
            if not department:
                raise HTTPException(status_code=404, detail="Department not found")
        except Exception:
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
async def update_election(election_id: str, election: ElectionUpdate, current_user: dict = Depends(get_admin_user)):
    try:
        election_obj_id = ObjectId(election_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid election ID")

    # Validate that facultyId is provided for Faculty elections
    if election.category == "Faculty" and election.facultyId is None:
        raise HTTPException(status_code=400, detail="Faculty ID is required for Faculty elections")

    # Validate that departmentId is provided for Department elections
    if election.category == "Department" and election.departmentId is None:
        raise HTTPException(status_code=400, detail="Department ID is required for Department elections")

    # Verify faculty exists if facultyId is provided
    if election.facultyId:
        try:
            faculty_id = validate_object_id(election.facultyId)
            if faculty_id is None:
                raise HTTPException(status_code=400, detail="Invalid faculty ID")
            faculty = await db.faculties.find_one({"_id": ObjectId(faculty_id)})
            if not faculty:
                raise HTTPException(status_code=404, detail="Faculty not found")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid faculty ID")

    # Verify department exists if departmentId is provided
    if election.departmentId:
        try:
            department_id = validate_object_id(election.departmentId)
            if department_id is None:
                raise HTTPException(status_code=400, detail="Invalid department ID")
            department = await db.departments.find_one({"_id": ObjectId(department_id)})
            if not department:
                raise HTTPException(status_code=404, detail="Department not found")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid department ID")

    # Determine status based on dates
    now = datetime.now(timezone.utc)
    status = None
    if election.startDate is not None and election.endDate is not None:
        if election.startDate <= now <= election.endDate:
            status = "active"
        elif election.endDate < now:
            status = "completed"
        else:
            status = "upcoming"

    update_data = {k: v for k, v in election.dict().items() if v is not None}
    if status:
        update_data["status"] = status
    update_data["updatedAt"] = datetime.now(timezone.utc)

    update_result = await db.elections.update_one(
        {"_id": election_obj_id},
        {"$set": update_data}
    )

    if update_result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Election not found")

    updated_election = await db.elections.find_one({"_id": election_obj_id})
    updated_election["_id"] = str(updated_election["_id"])
    return updated_election


@app.delete("/admin/elections/{election_id}", response_description="Delete an election")
async def delete_election(election_id: str, current_user: dict = Depends(get_admin_user)):
    try:
        election_obj_id = ObjectId(election_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid election ID")

    # Delete all candidates for this election
    await db.candidates.delete_many({"electionId": election_id})

    # Delete all votes for this election
    await db.votes.delete_many({"electionId": election_id})

    delete_result = await db.elections.delete_one({"_id": election_obj_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Election not found")

    return {"message": "Election and related data deleted successfully"}


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
    try:
        election_obj_id = ObjectId(electionId)
        election = await db.elections.find_one({"_id": election_obj_id})
        if not election:
            raise HTTPException(status_code=404, detail="Election not found")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid election ID")

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

    update_data["updatedAt"] = datetime.now(timezone.utc)

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
        candidate_obj_id = ObjectId(candidate_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid candidate ID")

    # Delete all votes for this candidate
    await db.votes.delete_many({"candidateId": candidate_id})

    delete_result = await db.candidates.delete_one({"_id": candidate_obj_id})

    if delete_result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Candidate not found")

    return {"message": "Candidate deleted successfully"}


@app.get("/admin/stats", response_description="Get admin dashboard stats")
async def get_admin_stats(current_user: dict = Depends(get_admin_user)):
    now = datetime.now(timezone.utc)

    # Count total users
    total_users = await db.users.count_documents({})

    # Count total elections
    total_elections = await db.elections.count_documents({})

    # Count active elections
    active_elections = await db.elections.count_documents({
        "startDate": {"$lte": now},
        "endDate": {"$gte": now}
    })

    # Count total candidates
    total_candidates = await db.candidates.count_documents({})

    # Count total votes
    total_votes = await db.votes.count_documents({})

    return {
        "totalUsers": total_users,
        "totalElections": total_elections,
        "activeElections": active_elections,
        "totalCandidates": total_candidates,
        "totalVotes": total_votes
    }


@app.get("/admin/elections/recent", response_description="Get recent elections for admin")
async def get_admin_recent_elections(current_user: dict = Depends(get_admin_user)):
    elections = await db.elections.find().sort("createdAt", DESCENDING).limit(5).to_list(5)

    for election in elections:
        election["_id"] = str(election["_id"])

    return elections


@app.get("/admin/users/recent", response_description="Get recent users for admin")
async def get_admin_recent_users(current_user: dict = Depends(get_admin_user)):
    users = await db.users.find().sort("createdAt", DESCENDING).limit(5).to_list(5)

    for user in users:
        user["_id"] = str(user["_id"])
        user.pop("password", None)

    return users
