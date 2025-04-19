-- SQLite_other_queries_fixed.sql
-- Complete test data insertion

-- Study plans
INSERT OR IGNORE INTO Study_plan (study_id, totalcredit, year) VALUES
  (1, 120, 2024),
  (2, 128, 2021);

-- Users (passwords hashed before insertion)
INSERT OR IGNORE INTO Users (user_id, username, email, password, isadmin) VALUES
  (1, 'fajr', 'fajr@qu.edu.qa', 'Qustudent1*', 0),
  (2, 'saja', 'saja@qu.edu.qa', 'Qustudent1*', 0),
  (3, 'maha', 'maha@qu.edu.qa', 'Qustudent1*', 0),
  (4, 'olla', 'olla@qu.edu.qa', 'Qustudent1*', 0),
  (5, 'sara', 'sara@qu.edu.qa', 'Qustudent1*', 0),
  (6, 'fatma', 'fatma@qu.edu.qa', 'Qustudent1*', 0),
  (7, 'aisha', 'aisha@qu.edu.qa', 'Qustudent1*', 0),
  (8, 'haya', 'haya@qu.edu.qa', 'Qustudent1*', 0),
  (9, 'hamda', 'hamda@qu.edu.qa', 'Qustudent1*', 0),
  (10, 'alya', 'alya@qu.edu.qa', 'Qustudent1*', 0),
  (11, 'noora', 'noora@qu.edu.qa', 'Qustudent1*', 1),
  (12, 'reem', 'reem@qu.edu.qa', 'Qustudent1*', 1),
  (13, 'Ahmed', 'ahmed@qu.edu.qa', 'Qustudent1*', 1),
  (14, 'Ali', 'ali@qu.edu.qa', 'Qustudent1*', 1),
  (15, 'Muneera', 'muneera@qu.edu.qa', 'Qustudent1*', 1),
  (16, 'Ghada', 'ghada@qu.edu.qa', 'Qustudent1*', 1);

-- Advisors
INSERT OR IGNORE INTO Advisors (advisor_id, name, specialization, user_id) VALUES
  (1, 'noora', 'Computer Science', 11),
  (2, 'reem', 'Computer Engineering', 12);

-- Students
INSERT OR IGNORE INTO Students (student_id, ssn, major, study_id, user_id) VALUES
  (1, '123-45-0001', 'fajr', 1, 2),
  (2, '123-45-0002', 'saja', 1, 2),
  (3, '123-45-0003', 'maha', 1, 2),
  (4, '123-45-0004', 'olla', 1, 2),
  (5, '123-45-0005', 'sara', 1, 2),
  (6, '123-45-0006', 'fatma', 1, 2),
  (7, '123-45-0007', 'aisha', 1, 2),
  (8, '123-45-0008', 'haya', 1, 2),
  (9, '123-45-0009', 'hamda', 1, 2),
  (10, '123-45-0010', 'alya', 1, 2);

-- IT Staff
INSERT OR IGNORE INTO It_staff (staff_id, permissions, user_id) VALUES
  (1, 'Admin', 11),
  (2, 'Manager', 12),
  (3, 'Technician', 13),
  (4, 'Support', 14);

-- Computer Science Courses
INSERT OR IGNORE INTO Courses (course_id, course_name, description, credithours, study_id) VALUES
  (151, 'Programming Concepts', 'Introduction to problem solving techniques...', 3, 1),
  (101, 'General Chemistry I', 'Basic concepts of general chemistry.', 3, 1),
  (103, 'Experimental General Chemistry I', 'Laboratory course...', 1, 1),
  (191, 'General Physics for Engineering I', 'Mechanics, waves, thermodynamics.', 3, 1),
  (192, 'Experimental General Physics for Engineering I', 'Lab experiments...', 1, 1),
  (1011, 'Calculus I', 'Differentiation and integration.', 3, 1),
  (1021, 'Calculus II', 'Integration techniques and applications.', 3, 1),
  (231, 'Linear Algebra', 'Matrix theory and eigenvalues.', 3, 1),
  (202, 'English Language I Post Foundation', 'Academic English communication skills.', 3, 1),
  (203, 'English Language II Post Foundation', 'Advanced academic writing and reading.', 3, 1),
  (121, 'History of Qatar', 'Overview of Qatar’s history.', 3, 1),
  (111, 'Islamic Culture', 'Overview of Islamic beliefs and culture.', 3, 1),
  (3004, 'Natural Science/Mathematics Package', 'Elective package.', 3, 1),
  (200, 'Computer Ethics', 'Ethical issues in computing.', 1, 1),
  (205, 'Discrete Structures for Computing', 'Logic, sets, relations, combinatorics.', 3, 1),
  (303, 'Data Structures', 'Lists, stacks, queues, trees, graphs.', 4, 1),
  (323, 'Design and Analysis of Algorithms', 'Divide-and-conquer, dynamic programming.', 3, 1),
  (351, 'Fundamentals of Database Systems', 'SQL, ER modeling.', 4, 1),
  (263, 'Computer Architecture and Organization I', 'Instruction sets, memory hierarchy.', 3, 1),
  (193, 'General Physics for Engineering II', 'Electricity and magnetism.', 3, 1),
  (194, 'Experimental General Physics for Engineering II', 'Optics lab.', 1, 1),
  (100, 'Arabic Language I', 'Arabic proficiency development.', 3, 1),
  (2001, 'Probability and Statistics for Engineers', 'Statistical inference and applications.', 3, 1),
  (310, 'Software Engineering', 'Software lifecycle, testing.', 4, 1),
  (355, 'Data Communication and Computer Networks I', 'OSI & TCP/IP models.', 4, 1),
  (380, 'Cybersecurity Fundamentals', 'Threats, vulnerabilities, cryptography.', 3, 1),
  (350, 'Web Development Fundamentals', 'HTML, CSS, JavaScript.', 3, 1),
  (405, 'Operating Systems', 'Process & memory management.', 4, 1),
  (3001, 'Numerical Methods', 'Algorithms for mathematical problems.', 3, 1),
  (493, 'Senior Project I', 'Capstone project design phase.', 3, 1),
  (499, 'Senior Project II', 'Implementation and testing phase.', 3, 1),
  (307, 'Introduction to Project Management and Entrepreneurship', 'PM principles and entrepreneurship.', 2, 1),
  (3011, 'Principles of Management', 'Planning, organizing, leading.', 3, 1),
  (3002, 'Humanities/Fine Arts Package', 'Elective package.', 3, 1),
  (3003, 'Social/Behavioral Sciences Package', 'Elective package.', 3, 1),
  (312, 'Mobile Application Development', 'Building mobile apps.', 3, 1),
  (356, 'Web Applications Design and Development', 'Advanced web frameworks.', 3, 1),
  (360, 'Data Science Fundamentals', 'Machine learning intro.', 3, 1),
  (373, 'Computer Graphics', 'Rendering and visualization.', 3, 1),
  (381, 'Applied Cryptography', 'Cryptographic algorithms.', 3, 1),
  (393, 'Modeling and Simulation', 'System modeling.', 3, 1),
  (399, 'Practical Training', 'Industry-based training.', 3, 1),
  (403, 'Artificial Intelligence', 'Problem-solving and learning.', 3, 1),
  (433, 'Multimedia Systems', 'Multimedia data processing.', 3, 1),
  (434, 'Game Design and Development', 'Game engines.', 3, 1),
  (451, 'Database Management Systems', 'Advanced DB concepts.', 3, 1),
  (453, 'Data Mining', 'Pattern extraction.', 3, 1),
  (460, 'Machine Learning', 'Supervised and unsupervised learning.', 3, 1),
  (465, 'Parallel Computing', 'Distributed systems.', 3, 1),
  (466, 'Information Retrieval', 'Search algorithms.', 3, 1),
  (480, 'Computer Vision', 'Image processing.', 3, 1),
  (488, 'Wireless Networks and Applications', 'Wireless protocols.', 3, 1),
  (497, 'Special Topics in Computing', 'Emerging CS topics.', 3, 1);

-- Computer Engineering Courses (study_id=2)
INSERT OR IGNORE INTO Courses (course_id, course_name, description, credithours, study_id) VALUES
  (151, 'Programming Concepts', 'Intro to problem solving...', 3, 2),
  (205, 'Discrete Structures for Computing', 'Logic and combinatorics.', 3, 2),
  (107, 'Engineering Skills and Ethics', 'Professional ethics.', 3, 2),
  (251, 'Object-Oriented Programming', 'Classes and inheritance.', 4, 2),
  (101, 'General Chemistry I', 'Basic chemistry.', 3, 2),
  (103, 'Experimental General Chemistry I', 'Chemistry lab.', 1, 2),
  (191, 'General Physics for Engineering I', 'Mechanics.', 3, 2),
  (192, 'Experimental General Physics for Engineering I', 'Mechanics lab.', 1, 2),
  (1011, 'Calculus I', 'Differentiation and integration.', 3, 2),
  (1021, 'Calculus II', 'Integration techniques.', 3, 2),
  (202, 'English Language I Post Foundation', 'Academic English.', 3, 2),
  (203, 'English Language II Post Foundation', 'Advanced writing.', 3, 2),
  (121, 'History of Qatar', 'Qatar history.', 3, 2),
  (111, 'Islamic Culture', 'Islamic beliefs.', 3, 2),
  (261, 'Digital Logic Design', 'Digital circuits.', 4, 2),
  (351, 'Signals and Systems', 'Signal processing.', 3, 2),
  (201, 'Electric Circuits', 'Circuit analysis.', 3, 2),
  (231, 'Fundamentals of Electronics', 'Semiconductor devices.', 3, 2),
  (211, 'Calculus III', 'Vector calculus.', 3, 2),
  (263, 'Computer Architecture and Organization I', 'CPU design.', 3, 2),
  (193, 'General Physics for Engineering II', 'EM and optics.', 3, 2),
  (194, 'Experimental General Physics for Engineering II', 'EM lab.', 1, 2),
  (200, 'Probability and Statistics for Engineers', 'Statistical methods.', 3, 2),
  (100, 'Arabic Language I', 'Arabic proficiency.', 3, 2),
  (355, 'Data Communication and Computer Networks I', 'Networking basics.', 4, 2),
  (364, 'Microprocessor Based Design', 'Microprocessor programming.', 4, 2),
  (363, 'Computer Architecture and Organization II', 'Advanced CPU topics.', 3, 2),
  (457, 'Data Communication and Computer Networks II', 'Routing and switching.', 3, 2),
  (370, 'Computer Engineering Practicum', 'Hands-on projects.', 1, 2),
  (476, 'Digital Signal Processing', 'Signal algorithms.', 4, 2),
  (405, 'Operating Systems', 'OS concepts.', 4, 2),
  (360, 'Engineering Economics', 'Project economics.', 3, 2),
  (217, 'Mathematics for Engineers', 'Advanced math.', 3, 2),
  (300, 'Numerical Methods', 'Numerical algorithms.', 3, 2),
  (498, 'Design Project I', 'Capstone design phase.', 3, 2),
  (499, 'Design Project II', 'Implementation and testing.', 3, 2),
  (462, 'Computer Interfacing', 'Embedded systems.', 3, 2),
  (3002, 'Humanities/Fine Arts Package', 'Elective package.', 3, 2),
  (3003, 'Social/Behavioral Sciences Package', 'Elective package.', 3, 2),
  (312, 'Mobile Application Development', 'Mobile dev.', 3, 2),
  (385, 'Computer Security', 'Security principles.', 3, 2),
  (480, 'Computer Vision', 'Image processing.', 3, 2),
  (488, 'Wireless Networks and Applications', 'Wireless protocols.', 3, 2),
  (399, 'Practical Training', 'Industry training.', 3, 2),
  (470, 'Modern Computer Organization', 'Advanced organization.', 3, 2),
  (471, 'Selected Topics in Computer Engineering', 'Emerging topics.', 3, 2),
  (474, 'Artificial Neural Networks', 'Neural networks.', 3, 2),
  (481, 'Modeling and Simulation of Digital Systems', 'Digital system modeling.', 3, 2),
  (482, 'Multimedia Networks', 'Multimedia networking.', 3, 2),
  (483, 'Introduction to Robotics', 'Control techniques.', 3, 2),
  (485, 'Fundamentals of Digital Image Processing', 'Image analysis.', 3, 2),
  (487, 'Hardware Software Co-Design', 'Co-design methods.', 3, 2);

-- Course Prerequisites
INSERT OR IGNORE INTO Course_prerequisite (course_id, pre_id) VALUES
  (251, 151),(203, 202),(1021, 1011),(231, 1011),(193, 191),(194, 192),(205, 151),
  (303, 251),(323, 303),(351, 303),(263, 303),(200, 1021),(310, 251),(350, 251),
  (405, 303),(380, 303),(355, 303),(300, 1021),(493, 310),(499, 493),(499, 350),
  (499, 405),(307, 310),(312, 151),(356, 350),(360, 200),(403, 323),(451, 351),
  (453, 451),(460, 360),(363, 263),(364, 263),(261, 191),(201, 191);

-- Study Plan Details
INSERT OR IGNORE INTO Study_plan_details (study_id, course_id, status) VALUES
  -- CS Plan 2024
  (1,151,'Core'),(1,205,'Core'),(1,107,'Core'),(1,251,'Core'),(1,101,'Core'),
  (1,103,'Core'),(1,191,'Core'),(1,192,'Core'),(1,1011,'Core'),(1,1021,'Core'),
  (1,202,'Core'),(1,203,'Core'),(1,231,'Core'),(1,121,'Core'),(1,111,'Core'),
  (1,310,'Core'),(1,355,'Core'),(1,380,'Core'),(1,350,'Core'),(1,405,'Core'),
  (1,3001,'Core'),(1,493,'Core'),(1,499,'Core'),(1,307,'Core'),(1,3011,'Core'),
  (1,3002,'Humanities/Fine Arts Package'),(1,3003,'Social/Behavioral Sciences Package'),
  (1,3004,'Natural Science/Mathematics Package'),(1,300,'Elective'),(1,312,'Elective'),
  (1,356,'Elective'),(1,360,'Elective'),(1,373,'Elective'),(1,381,'Elective'),
  (1,393,'Elective'),(1,403,'Elective'),(1,433,'Elective'),(1,434,'Elective'),
  (1,451,'Elective'),(1,453,'Elective'),(1,460,'Elective'),(1,465,'Elective'),
  (1,466,'Elective'),(1,480,'Elective'),(1,488,'Elective'),(1,497,'Elective'),
  -- CE Plan 2021
  (2,151,'Core'),(2,205,'Core'),(2,107,'Core'),(2,251,'Core'),(2,101,'Core'),
  (2,103,'Core'),(2,191,'Core'),(2,192,'Core'),(2,1011,'Core'),(2,1021,'Core'),
  (2,202,'Core'),(2,203,'Core'),(2,121,'Core'),(2,111,'Core'),(2,261,'Core'),
  (2,351,'Core'),(2,201,'Core'),(2,231,'Core'),(2,211,'Core'),(2,263,'Core'),
  (2,193,'Core'),(2,194,'Core'),(2,200,'Core'),(2,100,'Core'),(2,360,'Core'),
  (2,355,'Core'),(2,364,'Core'),(2,363,'Core'),(2,457,'Core'),(2,370,'Core'),
  (2,476,'Core'),(2,405,'Core'),(2,217,'Core'),(2,300,'Core'),(2,498,'Core'),
  (2,499,'Core'),(2,462,'Core'),(2,3002,'Humanities/Fine Arts Package'),
  (2,3003,'Social/Behavioral Sciences Package'),(2,474,'Elective'),(2,488,'Elective'),
  (2,485,'Elective'),(2,470,'Elective'),(2,481,'Elective'),(2,483,'Elective'),
  (2,399,'Elective');

-- Student Enrollments
INSERT OR IGNORE INTO student_enroll (student_id, course_id, grade, date) VALUES
  (1,151,'A','2024-02-10'),(1,205,'B+','2024-03-01'),(1,251,'A','2024-03-15'),
  (1,101,'B','2024-04-05'),(1,310,'A','2024-05-10'),(1,355,'B+','2024-05-25'),
  (2,303,'B+','2024-03-20'),(2,323,'A','2024-04-01'),(2,350,'B','2024-04-20'),
  (2,380,'C+','2024-05-05'),(2,405,'A','2024-05-15'),(3,493,'A','2024-06-01'),
  (3,499,'B+','2024-06-15'),(3,300,'A','2024-07-01'),(3,360,'B','2024-07-20'),
  (4,261,'B+','2024-02-10'),(4,351,'A','2024-03-05'),(4,201,'B','2024-03-25'),
  (4,231,'C','2024-04-10'),(4,211,'A','2024-04-25'),(4,263,'B','2024-05-10'),
  (5,355,'B+','2024-02-20'),(5,364,'C+','2024-03-05'),(5,457,'A','2024-03-25'),
  (5,476,'B','2024-04-10'),(5,405,'A','2024-04-20'),(6,498,'A','2024-05-10'),
  (6,499,'B','2024-05-25'),(6,462,'C','2024-06-05'),(6,470,'B+','2024-06-20'),
  (7,300,'A','2024-02-15'),(7,312,'B+','2024-03-01'),(7,356,'C','2024-03-20'),
  (7,403,'B','2024-04-05'),(7,460,'A','2024-04-20'),(8,433,'B+','2024-05-01'),
  (8,434,'A','2024-05-15'),(8,451,'B','2024-06-01'),(8,453,'C+','2024-06-20'),
  (9,474,'A','2024-02-10'),(9,480,'B+','2024-03-01'),(9,487,'C+','2024-03-20'),
  (9,488,'F','2024-04-05'),(10,485,'B','2024-05-01'),(10,481,'A','2024-05-15'),
  (10,482,'C','2024-06-01'),(10,399,'D+','2024-06-20');

-- Time slots
INSERT OR IGNORE INTO Time_Slots (slot_id, advisor_id, available_date, time_slot) VALUES
  (1,1,'2025-03-25','10:00-10:30'),
  (2,1,'2025-03-25','10:30-11:00'),
  (3,2,'2025-03-26','12:00-12:30'),
  (4,2,'2025-03-26','12:40-1:10');

-- Appointments
INSERT OR IGNORE INTO Appointments (appointment_id, student_id, slot_id, advisor_id, timestamp) VALUES
  (1,1,1,1,'2025-03-25 10:00:00'),
  (2,5,3,2,'2025-03-26 12:00:00');

-- Course updates
INSERT OR IGNORE INTO Course_Update (update_id, course_id, timestamp, description) VALUES
  (1,151,'2024-02-01 10:00:00','Updated course content for Programming Concepts'),
  (2,205,'2024-03-10 12:00:00','Added new topics to Discrete Structures'),
  (3,310,'2024-04-15 09:30:00','Software Engineering course outline updated'),
  (4,405,'2024-05-20 14:45:00','Operating Systems syllabus revised'),
  (5,350,'2024-06-05 13:00:00','Updated web development frameworks covered'),
  (6,493,'2024-07-18 11:10:00','New guidelines for Senior Project I'),
  (7,499,'2024-08-22 15:25:00','Senior Project II requirements updated'),
  (8,355,'2024-09-10 10:15:00','Networking protocols added to syllabus'),
  (9,476,'2024-10-05 12:40:00','Updated DSP course content'),
  (10,451,'2024-11-01 14:30:00','Database Management Systems improvements');

-- Student updates
INSERT OR IGNORE INTO Student_Update (student_id, update_id, description) VALUES
  (1,1,'Failed Calculus II and will retake next semester'),
  (2,2,'Enrolled in Senior Project I as a graduating senior'),
  (3,3,'Resigned from the elective course - Data Science Fundamentals'),
  (4,4,'Registered for elective course - Wireless Networks and Applications'),
  (5,5,'Failed Data Structures and retaking it in the current semester'),
  (6,6,'Taking Senior Project II after completing Senior Project I successfully'),
  (7,7,'Dropped Multimedia Networks elective due to schedule conflict'),
  (8,8,'Registered for elective course - Computer Vision'),
  (9,9,'Failed Operating Systems and will retake it in the next term'),
  (10,10,'Taking the final elective requirement with Mobile Application Development'),
  (9,11,'Graduation delayed due to not completing credit hour requirements'),
  (10,12,'Completed graduation requirements and is now eligible to graduate');

-- Browse history: students
INSERT OR IGNORE INTO Browse_Student (student_id, brows_date, faq_id) VALUES
  (1,'2024-01-15 10:30:00',101),
  (2,'2024-02-10 14:45:00',102),
  (3,'2024-03-05 09:20:00',103),
  (4,'2024-04-12 11:00:00',104),
  (5,'2024-05-18 16:25:00',105),
  (6,'2024-06-20 13:15:00',106),
  (7,'2024-07-25 08:50:00',107),
  (8,'2024-08-14 15:30:00',108),
  (9,'2024-09-07 17:40:00',109),
  (10,'2024-10-01 12:05:00',110);

-- Browse history: advisers
INSERT OR IGNORE INTO Browse_Adviser (advisor_id, brows_date, faq_id) VALUES
  (1,'2024-01-20 09:30:00',201),
  (2,'2024-02-25 11:15:00',202),
  (3,'2024-03-30 14:00:00',203),
  (4,'2024-04-28 16:45:00',204),
  (5,'2024-05-15 10:30:00',205),
  (6,'2024-06-22 12:20:00',206),
  (7,'2024-07-18 13:50:00',207),
  (8,'2024-08-09 15:35:00',208),
  (9,'2024-09-02 17:25:00',209),
  (10,'2024-10-11 08:45:00',210);
