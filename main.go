package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/satori/go.uuid"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
		"golang.org/x/crypto/bcrypt"
	"log"
	"time"
)

const (
	DbName = "RecipeBook"
	RecipeCollection = "Recipes"
	ChefCollection ="Chefs"

	jwtSecret = "secretname"
)
type Chef struct {
	ID string `json:"id" bson:"id"`
	Name string `json:"name" bson:"name"`
	Email string `json:"email" bson:"email"`
	Password string `json:"-, omitempty" bson:"Password"`
	Ts time.Time `json:"timestamp" bson:"timestamp"`

}

type Recipe struct {
	ID string `json:"id"`
	DishName string `json:"dish_name"`
	Chef         string `json:"chef"`
	Ingredients  string `json:"ingredients"`
	Instructions string `json:"instructions"`
	Ts time.Time `json:"timestamp"`
}

type Claims struct {
	UserId string `json:"user_id"`
	jwt.StandardClaims
}
 var dbClient *mongo.Client
func main()  {
	//connect to the database
	ctx, cancel := context.WithTimeout(context.Background(),10*time.Second)
	defer cancel()
	client, err :=mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatalf("could not connect to the db: %v/n", err)
	}

	dbClient = client
	err = dbClient.Ping(ctx, readpref.Primary())
	if err != nil{
		log.Fatalf("Mondo db not available: %v/n", err)
	}

	// create a gin router
	router := gin.Default()

	// define a single endpoint
	router.GET("/", welcomeHandler)

	// define crud endpoints


}

func welcomeHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"messae": "Hi Handler, Welcome to the Recipe Book API",
	})

}
func signUpChef(c *gin.Context){
	type SignupRequest struct {
		Name string `json:"name"`
		Email string `json:"email"`
		Password string `json:"password"`
	}
	var signupReq SignupRequest

	err := c.ShouldBindJSON(&signupReq)
	if err != nil{
		c.JSON(400, gin.H{
			"error": "Invalid request data",
		})
		return
	}
	query := bson.M{
		"email": signupReq.Email,
	}
	// search for duplicate users by email
	count, err := dbClient.Database(DbName).Collection(ChefCollection).CountDocuments(context.Background(), query)
	if err != nil{
		fmt.Println("error searching for user:", err)
		c.JSON(500, gin.H{
			"error":"error processing request, Please try again later",
		})
		return
	}
	// if count is greater than zero, then a user with that email already exists
	if count > 0 {
		c.JSON(500, gin.H{
			"error": "Email already exists, Please login or register with another email address",
		})
		return
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(signupReq.Password), bcrypt.DefaultCost)
	hashPassword := string(bytes)

	// generate user id
	userId := uuid.NewV4().String()
	chef := Chef{
		ID: userId,
		Name: signupReq.Name,
		Email: signupReq.Email,
		Password: hashPassword,
		Ts: time.Now(),
	}

	// store the users data
	_, err = dbClient.Database(DbName).Collection(ChefCollection).InsertOne(context.Background(),chef)
	if err != nil{
		fmt.Println("error saving user:", err)
		// if saving was unsuccessful
		c.JSON(500, gin.H{
			"erorr": "could not process request, error saving user",
		})
		return
	}

	// claims are the data that you want to store inside the jwt token
	// so whenever someone gives you a token you can decode it and get back the claims data

	claims := &Claims{
		UserId: chef.ID,
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	// generate token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,claims)
	jwtTokenString, err := token.SignedString([]byte(jwtSecret))

	c.JSON(200, gin.H{
		"Message": "Successful",
		"token": jwtTokenString,
		"data": chef,
	})

}