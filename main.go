package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/satori/go.uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"golang.org/x/crypto/bcrypt"
	"log"
	"os"
	"strings"
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
		log.Fatalf("Mondo db not available: %v\n", err)
	}

	// create a gin router
	router := gin.Default()

	// define a single endpoint
	router.GET("/", welcomeHandler)

	// define crud endpoints
	// c=create, r=retrieve, u=update, d=delete
	//create
	router.POST("/signup", signUpChef)
	router.POST("/login", loginChef)
	router.POST("/create", createRecipe)

	// retrieve

	// update

	// delete

	// run the server on port 3000
	port := os.Getenv("PORT")
	if port == ""{
		port = "3000"
	}
	_ = router.Run(":" + port)

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

func loginChef(c *gin.Context) {
	loginReq := struct {
		Email string `json:"email"`
		Password string `json:"password"`
	}{}
	err := c.ShouldBindJSON(&loginReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}
	var chef Chef
	query := bson.M{
		"email": loginReq.Email,
	}
	err = dbClient.Database(DbName).Collection(ChefCollection).FindOne(context.Background(), query).Decode(&chef)
	if err != nil {
		fmt.Println("error getting user fromm db: %v\n", err)
		c.JSON(500, gin.H{
			"eroor": "Unable to process request, Could not get User",

		})
		return
	}

	// if found compare and hash password
	err = bcrypt.CompareHashAndPassword([]byte(chef.Password), []byte(loginReq.Password))
	if err != nil {
		fmt.Println("error validating password: %v\n", err)
		c.JSON(500, gin.H{
			"error": "Invalid Login details",
		})
		return
	}
	// define claims data
	// create and return a jwt token with claims

	claims := &Claims{
		UserId: chef.ID,
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	// generate token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := token.SignedString([]byte(jwtSecret))

	c.JSON(200, gin.H{
		"message": "login successful",
		"token": jwtTokenString,
		"data": chef,
	})

}

func createRecipe(c *gin.Context){

	// create task for a specific user
	//  we need to find out the identity of the user
	//  this endpoint does not request for the users details like email or user id
	// as you've already gotten the details during login
	//  the request only contains the task and the jwt token

	//  the jwt token is what we use to identify the user
	// we generate this token during login or signup
	// because it is at that point that we confirm things like password and other security details we might be intersted in
	// you can't be asking the user for password at every endpoint
	// the jwt only contains the things we put inside
	// the only thing we need for our app to identify the user is the users id

	// for http request, the standard way the jwt is usually sent is as a request header
	// we need to get jwt token from request header using then key
	// for the jwt the key name is "Authorization"
	authorization := c.Request.Header.Get("Authorization")

	// we return an error if the token was not supplied

	if authorization == "" {
		c.JSON(400, gin.H{
			"error": "authentication token not supplied",
		})
		return
	}
	jwtToken := ""

	// split the authenthication token which looks like "Bearer asdsadsdsdsdsa........."
	//  so that we can get the second part of the string which is the actual jwt token
	splitTokenArray := strings.Split(authorization,"")
	if len(splitTokenArray) >1 {
		jwtToken = splitTokenArray[1]
	}
	// create an empty claims array to store the claims (userid,......)
	// decode the token to get claims
	claims := &Claims{}

	keyFunc := func(token *jwt.Token) (i interface{}, e error){
		return []byte(jwtSecret), nil
	}
	//  this function helps us validate the token
	// and if valid would store the claims inside the empty claims object we supplied to it (we supply a pointer)
	token, err := jwt.ParseWithClaims(jwtToken, claims,keyFunc)

	// we can check this token.valid boolean value to know if the token is valid
	if !token.Valid{
		c.JSON(400, gin.H{
			"error":"invalid jwt token",
		})
		return
	}
	// now that we have validated the token and we've been able to get the users identity
	// we can continue the request

	// create an empty task object to get the request body
	var recipeReq Recipe

	err = c.ShouldBindJSON(&recipeReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}
	// generate recipe id
	recipeId := uuid.NewV4().String()

	recipe := Recipe{
		ID: recipeId,
		DishName: recipeReq.DishName,
		Chef:     claims.UserId,
		Ingredients: recipeReq.Ingredients,
		Instructions: recipeReq.Instructions,
		Ts: time.Now(),
	}
	_, err = dbClient.Database(DbName).Collection(RecipeCollection).InsertOne(context.Background(), recipe)
	if err != nil{
		fmt.Println("error creating recipe", err)
		c.JSON(500, gin.H{
			"error":"unable to process request, error creating reicpe",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "succesfully added recipe",
		"data": recipe,
	})
}