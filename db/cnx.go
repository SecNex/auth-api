package db

type DB struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
}

type Connection struct {
	DB *DB
}

func NewDB(host string, port int, user string, password string, database string) *Connection {
	db := &DB{
		Host:     host,
		Port:     port,
		User:     user,
		Password: password,
		Database: database,
	}
	return NewConnection(db)
}

func NewConnection(db *DB) *Connection {
	return &Connection{
		DB: db,
	}
}
