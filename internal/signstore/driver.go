package signstore

// The pure-Go SQLite driver is imported for its database/sql registration
// side effect: signstore opens the database through database/sql only.
import _ "modernc.org/sqlite"
