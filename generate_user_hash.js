const crypto = require("crypto");
if (process.argv.length < 4) {
  console.log("Usage: node generate_user_hash.js <Pseudo> <Secret>");
  process.exit(1);
}
const pseudo = process.argv[2];
const secret = process.argv[3];
const hash = crypto.createHash("sha256").update(secret).digest("hex");
console.log(JSON.stringify({ pseudo, hash }, null, 2));
