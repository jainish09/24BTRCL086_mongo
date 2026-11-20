// Chapter 15: Multi-Tenant MongoDB Compound Indexes
// Ensures strict data isolation per organization and fast scoped queries

// 1. Cases collection compound index: tenant isolation + query filter
db.cases.createIndex({ "org_id": 1, "created_at": -1 });
db.cases.createIndex({ "org_id": 1, "status": 1 });
db.cases.createIndex({ "org_id": 1, "assigned_to": 1 });
db.cases.createIndex({ "id": 1, "org_id": 1 }, { unique: true });

// 2. Organisations collection indexes
db.organisations.createIndex({ "id": 1 }, { unique: true });
db.organisations.createIndex({ "slug": 1 }, { unique: true });

// 3. User organisation membership index
db.users.createIndex({ "org_id": 1, "role": 1 });
print("Chapter 15 Multi-Tenant MongoDB Indexes Created Successfully.");

