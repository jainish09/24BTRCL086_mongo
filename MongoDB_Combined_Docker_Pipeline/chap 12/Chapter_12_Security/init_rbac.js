// ==============================================================================
// LAB 12.1: RBAC Initialization & Custom Roles Setup
// Creates:
//   1. Collections: employees, departments, audit_logs in company_db
//   2. Sample Data including sensitive fields (salary, raw SSN)
//   3. Field-Level Redaction View: employees_safe (salary omitted, SSN masked)
//   4. Custom Roles:
//        - custom_read_safe_role (find on employees_safe and departments ONLY)
//        - custom_write_audit_role (find, insert, update, remove on audit_logs ONLY)
//   5. Application Users:
//        - app_user_read (assigned custom_read_safe_role)
//        - app_user_write (assigned custom_write_audit_role)
// ==============================================================================

const dbTarget = db.getSiblingDB("company_db");

print("================================================================");
print("[*] Chapter 12: Starting RBAC & Field-Level Redaction Setup...");
print("================================================================");

// ------------------------------------------------------------------------------
// 1. Create Base Collections & Populate Sample Data
// ------------------------------------------------------------------------------
print("[1/5] Populating 'employees' collection with sample records...");
dbTarget.employees.drop();
dbTarget.employees.insertMany([
  {
    emp_id: "EMP-1001",
    name: "Alice Johnson",
    department: "Engineering",
    position: "Senior Security Architect",
    salary: 145000,
    ssn: "111-22-3333",
    email: "alice.j@corp.local"
  },
  {
    emp_id: "EMP-1002",
    name: "Bob Smith",
    department: "Finance",
    position: "Financial Analyst",
    salary: 98000,
    ssn: "222-33-4444",
    email: "bob.s@corp.local"
  },
  {
    emp_id: "EMP-1003",
    name: "Carol White",
    department: "Human Resources",
    position: "HR Director",
    salary: 120000,
    ssn: "333-44-5555",
    email: "carol.w@corp.local"
  },
  {
    emp_id: "EMP-1004",
    name: "David Brown",
    department: "Engineering",
    position: "DevOps Engineer",
    salary: 115000,
    ssn: "444-55-6666",
    email: "david.b@corp.local"
  },
  {
    emp_id: "EMP-1005",
    name: "Eva Martinez",
    department: "Product",
    position: "Product Manager",
    salary: 130000,
    ssn: "555-66-7777",
    email: "eva.m@corp.local"
  }
]);

print("[2/5] Populating 'departments' and 'audit_logs' collections...");
dbTarget.departments.drop();
dbTarget.departments.insertMany([
  { dept_id: "D-01", name: "Engineering", floor: 4, head: "Alice Johnson" },
  { dept_id: "D-02", name: "Finance", floor: 2, head: "Bob Smith" },
  { dept_id: "D-03", name: "Human Resources", floor: 3, head: "Carol White" },
  { dept_id: "D-04", name: "Product", floor: 4, head: "Eva Martinez" }
]);

dbTarget.audit_logs.drop();
dbTarget.audit_logs.insertOne({
  log_id: "LOG-INIT-001",
  event: "SYSTEM_INITIALIZED",
  performed_by: "system_bootstrap",
  timestamp: new Date(),
  status: "SUCCESS"
});

// ------------------------------------------------------------------------------
// 2. Field-Level Redaction View (employees_safe)
// Excludes 'salary' completely and masks 'ssn' to '***-**-XXXX'
// ------------------------------------------------------------------------------
print("[3/5] Creating field-level redaction view 'employees_safe'...");
try {
  dbTarget.employees_safe.drop();
} catch (e) {}

dbTarget.createView("employees_safe", "employees", [
  {
    $project: {
      _id: 1,
      emp_id: 1,
      name: 1,
      department: 1,
      position: 1,
      email: 1,
      // 'salary' is explicitly omitted
      ssn: {
        $concat: [
          "***-**-",
          { $substrCP: ["$ssn", 7, 4] }
        ]
      }
    }
  }
]);
print("    [+] View 'employees_safe' created successfully.");

// ------------------------------------------------------------------------------
// 3. Custom MongoDB Roles (db.createRole)
// ------------------------------------------------------------------------------
print("[4/5] Configuring custom roles in database 'company_db'...");

// Drop roles if existing to guarantee idempotency
try { dbTarget.dropRole("custom_read_safe_role"); } catch (e) {}
try { dbTarget.dropRole("custom_write_audit_role"); } catch (e) {}

// Role A: Read-Only on specifically authorized collections
// Privileges: find on employees_safe (view) and departments ONLY
// Notice: NO privilege on raw 'employees' or 'audit_logs'
dbTarget.createRole({
  role: "custom_read_safe_role",
  privileges: [
    {
      resource: { db: "company_db", collection: "employees_safe" },
      actions: ["find"]
    },
    {
      resource: { db: "company_db", collection: "departments" },
      actions: ["find"]
    }
  ],
  roles: []
});
print("    [+] Role 'custom_read_safe_role' created.");

// Role B: Read, Insert, Update, Delete on specifically authorized collections
// Privileges: find, insert, update, remove on audit_logs ONLY
// Notice: NO privilege on 'employees', 'employees_safe', or 'departments'
dbTarget.createRole({
  role: "custom_write_audit_role",
  privileges: [
    {
      resource: { db: "company_db", collection: "audit_logs" },
      actions: ["find", "insert", "update", "remove"]
    }
  ],
  roles: []
});
print("    [+] Role 'custom_write_audit_role' created.");

// ------------------------------------------------------------------------------
// 4. Create Application Users with Custom Roles
// ------------------------------------------------------------------------------
print("[5/5] Creating application users...");

try { dbTarget.dropUser("app_user_read"); } catch (e) {}
try { dbTarget.dropUser("app_user_write"); } catch (e) {}

dbTarget.createUser({
  user: "app_user_read",
  pwd: "ReadPassword2026!",
  roles: [
    { role: "custom_read_safe_role", db: "company_db" }
  ]
});
print("    [+] User 'app_user_read' created with role 'custom_read_safe_role'.");

dbTarget.createUser({
  user: "app_user_write",
  pwd: "WritePassword2026!",
  roles: [
    { role: "custom_write_audit_role", db: "company_db" }
  ]
});
print("    [+] User 'app_user_write' created with role 'custom_write_audit_role'.");

print("================================================================");
print("[+] RBAC and Security initialization finished successfully.");
print("================================================================");
