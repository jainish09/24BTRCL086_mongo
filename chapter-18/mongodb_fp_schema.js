// Chapter 18: MongoDB False-Positive Detection Schema & Compound Indexes
// Collections: fp.full_threats and fp.candidates

// 1. Authoritative Full Threat Collection
db["fp.full_threats"].createIndex({ "value": 1 });
db["fp.full_threats"].createIndex({ "source": 1, "timestamp": -1 });
db["fp.full_threats"].createIndex({ "timestamp": -1 });
db["fp.full_threats"].createIndex({ "isFalsePositive": 1 });

// 2. False-Positive Candidate Collection
db["fp.candidates"].createIndex({ "value": 1 }, { unique: true });
db["fp.candidates"].createIndex({ "status": 1 });
db["fp.candidates"].createIndex({ "source": 1 });
db["fp.candidates"].createIndex({ "detectionReason": 1 });

print("Chapter 18 MongoDB fp.full_threats and fp.candidates indexes created successfully.");

