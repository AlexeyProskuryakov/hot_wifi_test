package auth

import (
	"context"
	"log"
	"time"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/x/bsonx"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func yieldIndex(key string, asc int, unique bool) mongo.IndexModel {
	index := mongo.IndexModel{}
	index_options := &options.IndexOptions{}
	index_options.SetBackground(true)
	index_options.SetUnique(unique)

	keys := bsonx.Doc{{Key: key, Value: bsonx.Int32(int32(asc))}}
	index.Keys = keys
	index.Options = index_options
	return index
}

func yieldSessionIndexTtl(key string) mongo.IndexModel {
	index := mongo.IndexModel{}
	index_options := &options.IndexOptions{}
	index_options.SetBackground(true)
	index_options.SetExpireAfterSeconds(int32(SESSION_TTL))
	keys := bsonx.Doc{{Key: key, Value: bsonx.Int32(-1)}}
	index.Keys = keys
	index.Options = index_options
	return index
}

func InitDb() (*mongo.Database, error) {
	uri := fmt.Sprintf("mongodb://%s:%s@%s:%v/%s", DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME)

	log.Printf("Connect to %s", uri)
	client, err := mongo.NewClient(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		return nil, err
	}
	db := client.Database(DB_NAME)
	return db, nil
}

type AccountsStorage struct {
	Accounts *mongo.Collection
}

type PolicyStorage struct {
	Policy *mongo.Collection
}

type SessionsStorage struct {
	Sessions *mongo.Collection
}

func NewAccountsStorage() (*AccountsStorage, error) {
	db, err := InitDb()
	if err != nil {
		return nil, err
	}

	accountsCollection := db.Collection("accounts")
	accountsCollection.Indexes().CreateMany(
		context.TODO(),
		[]mongo.IndexModel{
			yieldIndex("login", 1, true),
			yieldIndex("isExternalAccount", 1, false),
		})

	result := AccountsStorage{Accounts: accountsCollection}
	return &result, nil
}

func NewPolicyStorage() (*PolicyStorage, error) {
	db, err := InitDb()
	if err != nil {
		return nil, err
	}
	policyCollection := db.Collection("policy")
	result := PolicyStorage{Policy: policyCollection}
	return &result, nil
}

func NewSessionStorage() (*SessionsStorage, error) {
	db, err := InitDb()
	if err != nil {
		return nil, err
	}
	sessionsCollection := db.Collection("sessions")
	sessionsCollection.Indexes().CreateMany(
		context.TODO(),
		[]mongo.IndexModel{
			yieldIndex("login", -1, true),
			yieldSessionIndexTtl("token"),
		})

	result := SessionsStorage{Sessions: sessionsCollection}
	return &result, nil
}

func (st *SessionsStorage) SetSession(session *Session) error {
	uOpts := options.UpdateOptions{}
	uOpts.SetUpsert(true)
	_, err := st.Sessions.UpdateOne(context.TODO(), bson.M{"login": session.Login}, bson.M{"$set": session}, &uOpts)
	if err != nil {
		log.Printf("Error at set account : %s", err)
		return err
	}
	return nil
}

func (st *SessionsStorage) GetSession(token string) (*Session, error) {
	res := st.Sessions.FindOne(context.TODO(), bson.M{"token": token})
	s := Session{}
	err := res.Decode(&s)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		log.Printf("Error at decode session: %s", err)
		return nil, err
	}
	return &s, nil
}

func (st *SessionsStorage) DeleteSession(login string) error {
	_, err := st.Sessions.DeleteOne(context.TODO(), bson.M{"login": login})
	if err != nil {
		log.Printf("Error at deleting session %s", err)
		return err
	}
	return nil
}

func (st *SessionsStorage) GetSessionByLogin(login string) (*Session, error) {
	res := st.Sessions.FindOne(context.TODO(), bson.M{"login": login})
	s := Session{}
	err := res.Decode(&s)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		log.Printf("Error at decode session: %s", err)
		return nil, err
	}
	return &s, nil
}

func (st *AccountsStorage) SetAccount(account *Account) (interface{}, error) {
	uOpts := options.UpdateOptions{}
	uOpts.SetUpsert(true)
	result, err := st.Accounts.UpdateOne(context.TODO(), bson.M{"login": account.Login}, bson.M{"$set": account}, &uOpts)
	if err != nil {
		log.Printf("Error at set account : %s", err)
		return nil, err
	}
	return result.UpsertedID, nil
}

func (st *AccountsStorage) GetAccount(login string) (*Account, error) {
	result := st.Accounts.FindOne(context.TODO(), bson.M{"login": login})
	var acc Account
	err := result.Decode(&acc)
	if err == mongo.ErrNoDocuments {
		return nil, nil
	}
	if err != nil {
		log.Printf("Error at get account : %s", err)
		return nil, err
	}
	return &acc, err
}

func (st *AccountsStorage) GetAccountById(id string) (*Account, error) {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		log.Printf("Can not get object id from %s : %s", id, err)
		return nil, err
	}
	result := st.Accounts.FindOne(context.TODO(), bson.D{{"_id", objectID}})
	var acc Account
	err = result.Decode(&acc)
	if err != nil {
		log.Printf("Error at get account : %s", err)
		return nil, err
	}
	return &acc, err
}

func (st *AccountsStorage) GetAccountsViews() ([]AccountView, error) {
	cursor, err := st.Accounts.Find(context.TODO(), bson.M{})
	if err != nil {
		log.Printf("Error at get accounts : %s", err)
		return nil, err
	}
	result := []AccountView{}
	for ; cursor.Next(context.TODO()); {
		var acc AccountView
		err := cursor.Decode(&acc)
		if err != nil {
			log.Printf("Error at decoding account %s", err)
			continue
		}
		result = append(result, acc)
	}
	return result, nil
}

func (at *AccountsStorage) DeleteAccount(id string) error {
	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		log.Printf("Can not get object id from %s : %s", id, err)
		return err
	}
	_, err = at.Accounts.DeleteOne(context.TODO(), bson.D{{"_id", objectID}})
	if err != nil {
		log.Printf("Error at delete account : %s", err)
		return err
	}
	return nil
}

func (st *PolicyStorage) SetPolicy(p *PasswordPolicy) (error) {
	upsert := true
	upsertOpts := options.UpdateOptions{Upsert: &upsert}
	_, err := st.Policy.UpdateOne(context.TODO(), bson.M{}, bson.M{"$set": p}, &upsertOpts)
	if err != nil {
		log.Printf("Error at update policy: %s", err)
		return err
	}
	return nil
}

func (st *PolicyStorage) GetPolicy() (*PasswordPolicy, error) {
	result := st.Policy.FindOne(context.TODO(), bson.M{})
	var policy PasswordPolicy
	err := result.Decode(&policy)
	if err == mongo.ErrNoDocuments {
		return DEFAULT_POLICY, nil
	}
	if err != nil {
		log.Printf("Error at read policy: %s", err)
		return nil, err
	}
	return &policy, err
}
