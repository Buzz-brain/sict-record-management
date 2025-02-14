const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Connect to MongoDB
mongoose.connect('mongodb+srv://chinomsochristian03:ahYZxLh5loYrfgss@cluster0.dmkcl.mongodb.net/computerize?retryWrites=true&w=majority');
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

app.use(express.json());
app.set('view engine', 'ejs');
app.use(express.static('public'));

app.get('/', (req, res) => {
  res.render('login');
});
app.get('/login', (req, res) => {
  res.render('login');
});
app.get('/adminlogin', (req, res) => {
  res.render('adminlogin');
});
app.get('/dashboard', (req, res) => {
  res.render('dashboard');
});

// Define student schema
const studentSchema = new mongoose.Schema({
  name: String,
  regNo: String,
  dept: String,
  level: String,
  password: String,
  personalRecords: {
    dateOfBirth: String,
    stateOfOrigin: String,
    religion: String,
    lga: String,
    sex: String,
    phoneNumber: String,
    genotype: String,
    medicalCondition: String,
    academicStatus: String
  }
});

// Define staff schema
const staffSchema = new mongoose.Schema({
  name: String,
  staffId: String,
  dept: String,
  password: String,
  personalRecords: {
    dateOfBirth: String,
    sex: String,
    contactInfo: String,
    courseAllocation: String,
    stateOfOrigin: String,
    permanentHomeAddress: String,
    genotype: String,
    medicalCondition: String
  }
});

// Define super admin schema
const superAdminSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: String 
});

// Define personalRecordUnitAdmin schema
const personalRecordUnitAdminSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  department: String, // IFT, CSC, CYB, or SOE
  role: String, // 'personal-record-unit-admin'
});


// Create models
const Student = mongoose.model('Student', studentSchema);
const Staff = mongoose.model('Staff', staffSchema);
const SuperAdmin = mongoose.model('SuperAdmin', superAdminSchema);
const PersonalRecordUnitAdmin = mongoose.model('PersonalRecordUnitAdmin', personalRecordUnitAdminSchema);


// Generate JWT token
const generateToken = (superAdmin) => {
  const token = jwt.sign({ _id: superAdmin._id }, 'secretkey', { expiresIn: '1h' });
  return token;
};

const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.header('Authorization');
    if (!token) return res.status(401).send('Access denied. No token provided.');
    const bearerToken = token.split(' ')[1];
    try {
      const decoded = jwt.verify(bearerToken, 'secretkey');
      req.user = decoded;
      const superAdmin = await SuperAdmin.findOne({ _id: req.user._id });
      if (superAdmin) {
        req.user.role = 'super-admin';
        next();
      } else {
        const personalRecordUnitAdmin = await PersonalRecordUnitAdmin.findOne({ _id: req.user._id });
        if (personalRecordUnitAdmin) {
          req.user.role = 'personal-record-unit-admin';
          req.user.department = personalRecordUnitAdmin.department;
          next();
        } else {
          return res.status(403).json({ message: 'Forbidden' });
        }
      }
    } catch (ex) {
      res.status(400).send('Invalid token.');
    }
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};





// ADMIN ROUTES

// Super Admin login
app.post('/login/superadmin', async (req, res) => {
  try {
    const { email, password } = req.body;
    const superAdmin = await SuperAdmin.findOne({ email });
    if (!superAdmin) return res.status(401).json({ message: 'Invalid email or password.' });
    const isValidPassword = bcrypt.compareSync(password, superAdmin.password);
    if (!isValidPassword) return res.status(401).json({ message: 'Invalid email or password.' });
    const token = generateToken(superAdmin);
    res.json({ token });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Login Personal Record Unit Admin
app.post('/login/personal-record-unit-admin', async (req, res) => {
  try {
    const { email, password } = req.body;
    const personalRecordUnitAdmin = await PersonalRecordUnitAdmin.findOne({ email });
    if (!personalRecordUnitAdmin) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const isValidPassword = bcrypt.compareSync(password, personalRecordUnitAdmin.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    const token = jwt.sign({ _id: personalRecordUnitAdmin._id, department: personalRecordUnitAdmin.department, role: 'personal-record-unit-admin' }, 'secretkey', { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});




// ROLE-BASED ACCESS CONTROL 


// CREATE OTHER ADMINS

// Super Admin creates other admins - personal-record-unit-admin
app.post('/create-personal-record-unit-admin', authenticateAdmin, async (req, res) => {
  try {
    if (!['super-admin'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const { name, email, password, department } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const personalRecordUnitAdmin = new PersonalRecordUnitAdmin({
      name,
      email,
      password: hashedPassword,
      department,
      role: 'personal-record-unit-admin',
    });
    await personalRecordUnitAdmin.save();
    res.json({ message: 'Personal Record Unit Admin created successfully!' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


// CREATE STUDENT AND STAFF 

// Super Admin and personal-record-unit-admin for each dept preregisters students
app.post('/preregister/student', authenticateAdmin, async (req, res) => {
  try {
    console.log(req.body.dept, req.user)

    if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    if (req.user.role === 'personal-record-unit-admin' && req.body.dept !== req.user.department) {
      return res.status(403).json({ message: 'Forbidden' });
    }

    
    const { name, regNo, dept } = req.body;
    const student = new Student({
      name,
      regNo,
      dept,
      password: regNo,
      personalRecords: {
        dateOfBirth: "",
        stateOfOrigin: "",
        religion: "",
        lga: "",
        sex: "",
        phoneNumber: "",
        genotype: "",
        medicalCondition: "",
        academicStatus: "active"
      }
    });
    await student.save();
    res.json({ message: 'Student preregistered successfully!' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Super Admin and personal-record-unit-admin for each dept preregisters staff
app.post('/preregister/staff', authenticateAdmin, async (req, res) => {
  try {
    if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    if (req.user.role === 'personal-record-unit-admin' && req.body.dept !== req.user.department) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const { name, staffId, dept } = req.body;
    const staff = new Staff({
      name,
      staffId,
      dept,
      password: staffId,
      personalRecords: {
        dateOfBirth: "",
        sex: "",
        contactInfo: "",
        courseAllocation: "",
        stateOfOrigin: "",
        permanentHomeAddress: "",
        genotype: "",
        medicalCondition: ""
      }
    });
    await staff.save();
    res.json({ message: 'Staff preregistered successfully!' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


//  UPDATE  STUDENT AND STAFF RECORDS

// Super Admin and personal-record-unit-admin for each dept updates student personal records
app.patch('/admin/update/student/:regNo', authenticateAdmin, async (req, res) => {
  try {
    if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const regNo = req.params.regNo;
    const student = await Student.findOne({ regNo });
    if (!student) {
      return res.status(404).json({ message: 'Student not found!' });
    }
    if (req.user.role === 'personal-record-unit-admin' && student.dept !== req.user.department) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    await Student.updateOne({ regNo }, { $set: { personalRecords: req.body.personalRecords } });
    res.json({ message: 'Student personal records updated successfully!' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Super Admin and personal-record-unit-admin for each dept updates staff personal records
app.patch('/admin/update/staff/:staffId', authenticateAdmin, async (req, res) => {
  try {
    if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const staffId = req.params.staffId;
    const staff = await Staff.findOne({ staffId });
    if (!staff) {
      return res.status(404).json({ message: 'Staff not found!' });
    }
    if (req.user.role === 'personal-record-unit-admin' && staff.dept !== req.user.department) {
      return res.status(403).json({ message: 'Forbidden' });
    }
    await Staff.updateOne({ staffId }, { $set: { personalRecords: req.body.personalRecords } });
    res.json({ message: 'Staff personal records updated successfully!' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


// VIEW STUDENT AND STAFF RECORDS

// View student records
app.get('/view/students', authenticateAdmin, async (req, res) => {
  try {
  if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
  return res.status(403).json({ message: 'Forbidden' });
  }
  let query = {};
  if (req.user.role === 'personal-record-unit-admin') {
  query.dept = req.user.department;
  }
  const students = await Student.find(query);
  res.json(students);
  } catch (err) {
  res.status(400).json({ message: err.message });
  }
  });
  
  
// View staff records
app.get('/view/staffs', authenticateAdmin, async (req, res) => {
  try {
  if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
  return res.status(403).json({ message: 'Forbidden' });
  }
  let query = {};
  if (req.user.role === 'personal-record-unit-admin') {
  query.dept = req.user.department;
  }
  const staffs = await Staff.find(query);
  res.json(staffs);
  } catch (err) {
  res.status(400).json({ message: err.message });
  }
  });


// DELETE STUDENT AND STAFF RECORDS

// Delete student records
app.delete('/delete/student/:regNo', authenticateAdmin, async (req, res) => {
  try {
  if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
  return res.status(403).json({ message: 'Forbidden' });
  }
  const regNo = req.params.regNo;
  const student = await Student.findOne({ regNo });
  if (!student) {
  return res.status(404).json({ message: 'Student not found!' });
  }
  if (req.user.role === 'personal-record-unit-admin' && student.dept !== req.user.department) {
  return res.status(403).json({ message: 'Forbidden' });
  }
  await Student.deleteOne({ regNo });
  res.json({ message: 'Student deleted successfully!' });
  } catch (err) {
  res.status(400).json({ message: err.message });
  }
  });
  
// Delete staff records
app.delete('/delete/staff/:staffId', authenticateAdmin, async (req, res) => {
  try {
  if (!['super-admin', 'personal-record-unit-admin'].includes(req.user.role)) {
  return res.status(403).json({ message: 'Forbidden' });
  }
  const staffId = req.params.staffId;
  const staff = await Staff.findOne({ staffId });
  if (!staff) {
  return res.status(404).json({ message: 'Staff not found!' });
  }
  if (req.user.role === 'personal-record-unit-admin' && staff.dept !== req.user.department) {
  return res.status(403).json({ message: 'Forbidden' });
  }
  await Staff.deleteOne({ staffId });
  res.json({ message: 'Staff deleted successfully!' });
  } catch (err) {
  res.status(400).json({ message: err.message });
  }
  });



















  const authenticateStudentOrStaff = async (req, res, next) => {
    try {
    const token = req.header('Authorization');
    if (!token) return res.status(401).send('Access denied. No token provided.');
    const bearerToken = token.split(' ')[1];
    try {
    const decoded = jwt.verify(bearerToken, 'secretkey');
    req.user = decoded;
    next();
    } catch (ex) {
    res.status(400).send('Invalid token.');
    }
    } catch (err) {
    res.status(400).json({ message: err.message });
    }
    };
    




// STUDENT AND STAFF ROUTES


// Student login
app.post('/login/student', async (req, res) => {
  try {
  const { regNo, password } = req.body;
  const student = await Student.findOne({ regNo });
  if (!student) {
  return res.status(401).json({ message: 'Invalid credentials!' });
  }
  if (student.password === regNo) {
  // If password is the registration number, prompt to change password
  res.json({ message: 'Please change your password!', regNo: student.regNo });
  } else {
  // If password has been changed, compare with hashed password
  const isValidPassword = await bcrypt.compare(password, student.password);
  if (!isValidPassword) {
  return res.status(401).json({ message: 'Invalid credentials!' });
  }
  const token = jwt.sign({ _id: student._id, regNo: student.regNo }, 'secretkey', { expiresIn: '1h' });
  res.json({ message: 'Logged in successfully!', token });
  }
  } catch (err) {
  res.status(400).json({ message: err.message });
  }
  });
  
// Staff login
app.post('/login/staff', async (req, res) => {
  try {
  const { staffId, password } = req.body;
  const staff = await Staff.findOne({ staffId });
  if (!staff) {
  return res.status(401).json({ message: 'Invalid credentials!' });
  }
  if (staff.password === staffId) {
  // If password is the staff ID, prompt to change password
  res.json({ message: 'Please change your password!', staffId: staff.staffId });
  } else {
  // If password has been changed, compare with hashed password
  const isValidPassword = await bcrypt.compare(password, staff.password);
  if (!isValidPassword) {
  return res.status(401).json({ message: 'Invalid credentials!' });
  }
  const token = jwt.sign({ _id: staff._id, staffId: staff.staffId }, 'secretkey', { expiresIn: '1h' });
  res.json({ message: 'Logged in successfully!', token });
  }
  } catch (err) {
  res.status(400).json({ message: err.message });
  }
  });
  
// Change student password
app.patch('/change-password/student/:regNo', async (req, res) => {
  try {
  const regNo = req.params.regNo;
  const { newPassword } = req.body;
  const student = await Student.findOne({ regNo });
  if (!student) {
  return res.status(404).json({ message: 'Student not found!' });
  }
  const hashedPassword = await bcrypt.hash(newPassword, 10);
  student.password = hashedPassword;
  await student.save();
  res.json({ message: 'Password changed successfully!' });
  } catch (err) {
  res.status(400).json({ message: err.message });
  }
  });
  
// Change staff password
app.patch('/change-password/staff/:staffId', async (req, res) => {
try {
const staffId = req.params.staffId;
const { newPassword } = req.body;
const staff = await Staff.findOne({ staffId });
if (!staff) {
return res.status(404).json({ message: 'Staff not found!' });
}
const hashedPassword = await bcrypt.hash(newPassword, 10);
staff.password = hashedPassword;
await staff.save();
res.json({ message: 'Password changed successfully!' });
} catch (err) {
res.status(400).json({ message: err.message });
}
});

// Student dashboard
app.get('/dashboard/student/:regNo', authenticateStudentOrStaff, async (req, res) => {
  try {
    const regNo = req.params.regNo;
    const student = await Student.findOne({ regNo });
    if (!student) {
      return res.status(404).json({ message: 'Student not found!' });
    }
    res.json({
      name: student.name,
      regNo: student.regNo,
      dept: student.dept,
      personalRecords: student.personalRecords
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Staff dashboard
app.get('/dashboard/staff/:staffId', authenticateStudentOrStaff, async (req, res) => {
  try {
    const staffId = req.params.staffId;
    const staff = await Staff.findOne({ staffId });
    if (!staff) {
      return res.status(404).json({ message: 'Staff not found!' });
    }
    res.json({
      name: staff.name,
      staffId: staff.staffId,
      dept: staff.dept,
      personalRecords: staff.personalRecords
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Update student personal records
app.patch('/update/student/:regNo', authenticateStudentOrStaff, async (req, res) => {
  try {
    const regNo = req.params.regNo;
    const student = await Student.findOne({ regNo });
    if (!student) {
      return res.status(404).json({ message: 'Student not found!' });
    }
    await Student.updateOne({ regNo }, { $set: { 
      personalRecords: req.body.personalRecords
    } });
    res.json({ message: 'Student personal records updated successfully!' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Update staff personal records
app.patch('/update/staff/:staffId', authenticateStudentOrStaff, async (req, res) => {
  try {
    const staffId = req.params.staffId;
    const staff = await Staff.findOne({ staffId });
    if (!staff) {
      return res.status(404).json({ message: 'Staff not found!' });
    }
    await Staff.updateOne({ staffId }, { $set: { 
      personalRecords: req.body.personalRecords
    } });
    
    res.json({ message: 'Staff personal records updated successfully!' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


// Start server
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});


















// Update student personal records
// app.patch('/update/student/:regNo', authenticatePersonalRecordUnitAdmin, async (req, res) => {
//   try {
//     const regNo = req.params.regNo;
//     const student = await Student.findOne({ regNo });
//     if (!student) {
//       return res.status(404).json({ message: 'Student not found!' });
//     }
//     if (student.dept !== req.user.department) {
//       return res.status(403).json({ message: 'Forbidden' });
//     }
//     await Student.updateOne({ regNo }, { $set: { personalRecords: req.body.personalRecords } });
//     res.json({ message: 'Student personal records updated successfully!' });
//   } catch (err) {
//     res.status(400).json({ message: err.message });
//   }
// });

// // Update staff personal records
// app.patch('/update/staff/:staffId', authenticatePersonalRecordUnitAdmin, async (req, res) => {
//   try {
//     const staffId = req.params.staffId;
//     const staff = await Staff.findOne({ staffId });
//     if (!staff) {
//       return res.status(404).json({ message: 'Staff not found!' });
//     }
//     if (staff.dept !== req.user.department) {
//       return res.status(403).json({ message: 'Forbidden' });
//     }
//     await Staff.updateOne({ staffId }, { $set: { personalRecords: req.body.personalRecords } });
//     res.json({ message: 'Staff personal records updated successfully!' });
//   } catch (err) {
//     res.status(400).json({ message: err.message });
//   }
// });





