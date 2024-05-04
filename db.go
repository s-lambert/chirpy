package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"sort"
	"sync"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}

type Chirp struct {
	Body     string `json:"body"`
	Id       int    `json:"id"`
	AuthorId int    `json:"author_id"`
}

type User struct {
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Id       int    `json:"id"`
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  map[int]User  `json:"users"`
}

func NewDB(path string) (*DB, error) {
	newDB := DB{
		path: path,
		mux:  &sync.RWMutex{},
	}
	err := newDB.ensureDB()
	if err != nil {
		return nil, err
	}
	return &newDB, nil
}

func (db *DB) CreateChirp(body string, authorId int) (Chirp, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}
	maxId := 0
	for _, chirp := range dbStruct.Chirps {
		if chirp.Id > maxId {
			maxId = chirp.Id
		}
	}

	maxId += 1
	newChirp := Chirp{
		Id:       maxId,
		Body:     body,
		AuthorId: authorId,
	}

	dbStruct.Chirps[newChirp.Id] = newChirp
	err = db.writeDB(dbStruct)
	if err != nil {
		return Chirp{}, err
	}

	return newChirp, nil
}

func (db *DB) DeleteChirp(id int) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return err
	}
	delete(dbStruct.Chirps, id)
	err = db.writeDB(dbStruct)
	return err
}

func Values[M ~map[K]V, K comparable, V any](m M) []V {
	r := make([]V, 0, len(m))
	for _, v := range m {
		r = append(r, v)
	}
	return r
}

func (db *DB) GetChirps() ([]Chirp, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return []Chirp{}, err
	}

	orderedChirps := Values(dbStruct.Chirps)
	sort.Slice(orderedChirps, func(i, j int) bool { return orderedChirps[i].Id < orderedChirps[j].Id })
	return orderedChirps, nil
}

func (db *DB) GetChirp(id int) (Chirp, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	chirp, ok := dbStruct.Chirps[id]
	if !ok {
		return Chirp{}, errors.New("Chirp not found")
	}
	return chirp, nil
}

func (db *DB) CreateUser(email, password string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, nil
	}
	maxId := 0
	for _, user := range dbStruct.Users {
		if user.Id > maxId {
			maxId = user.Id
		}
	}

	maxId += 1
	newUser := User{
		Id:       maxId,
		Email:    email,
		Password: password,
	}

	dbStruct.Users[newUser.Id] = newUser
	err = db.writeDB(dbStruct)
	if err != nil {
		return User{}, err
	}

	return newUser, nil
}

func (db *DB) UpdateUser(id int, newEmail, newPassword string) (User, error) {
	db.mux.Lock()
	defer db.mux.Unlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	existingUser, ok := dbStruct.Users[id]
	if !ok {
		return User{}, errors.New("Could not find existing user")
	}

	if newPassword != "" {
		existingUser.Password = newPassword
	}
	if newEmail != "" {
		existingUser.Email = newEmail
	}

	dbStruct.Users[existingUser.Id] = existingUser

	err = db.writeDB(dbStruct)
	if err != nil {
		return User{}, err
	}

	return existingUser, nil
}

func (db *DB) GetUsers() ([]User, error) {
	db.mux.Lock()
	defer db.mux.RUnlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return []User{}, err
	}

	orderedUsers := Values(dbStruct.Users)
	sort.Slice(orderedUsers, func(i, j int) bool { return orderedUsers[i].Id < orderedUsers[j].Id })
	return orderedUsers, nil
}

func (db *DB) GetUser(id int) (User, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, nil
	}

	user, ok := dbStruct.Users[id]
	if !ok {
		return User{}, errors.New("User not found")
	}
	return user, nil
}

func (db *DB) GetUserByEmail(email string) (User, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	dbStruct, err := db.loadDB()
	if err != nil {
		return User{}, nil
	}

	for _, user := range dbStruct.Users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, errors.New("User not found")
}

func (db *DB) ensureDB() error {
	_, err := os.Stat(db.path)

	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	blankDBStruct := DBStructure{}
	jsonBytes, parseErr := json.Marshal(blankDBStruct)
	if parseErr != nil {
		return parseErr
	}

	writeErr := os.WriteFile(db.path, jsonBytes, 0666)
	if writeErr != nil {
		log.Fatal(writeErr)
	}
	return nil
}

func (db *DB) loadDB() (DBStructure, error) {
	contents, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, nil
	}

	var dbStruct DBStructure
	if err := json.Unmarshal(contents, &dbStruct); err != nil {
		return DBStructure{}, err
	}
	if dbStruct.Chirps == nil {
		dbStruct.Chirps = make(map[int]Chirp)
	}
	if dbStruct.Users == nil {
		dbStruct.Users = make(map[int]User)
	}

	return dbStruct, nil
}

func (db *DB) writeDB(dbStruct DBStructure) error {
	jsonBytes, parseErr := json.Marshal(dbStruct)
	if parseErr != nil {
		return parseErr
	}
	writeErr := os.WriteFile(db.path, jsonBytes, 0666)
	return writeErr
}
