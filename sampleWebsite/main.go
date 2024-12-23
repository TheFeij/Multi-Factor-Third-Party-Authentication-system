package main

import (
	"bytes"
	"encoding/json"
	"github.com/gin-contrib/cors"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()
	// CORS middleware configuration
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"}
	config.AllowMethods = []string{"GET", "POST", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type"}
	router.Use(cors.New(config))

	// Serve the profile page (HTML template)
	router.LoadHTMLGlob("./sampleWebsite/*.html") // Make sure you have an HTML file at "templates/profile.html"
	router.Static("/static", "./sampleWebsite")

	// Handler for the redirected request
	router.GET("/callback", func(context *gin.Context) {
		// Extract the token (authorization code) from query parameters
		token := context.Query("token")
		if token == "" {
			context.JSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
			return
		}

		// Create a JSON payload with the access token
		payload := map[string]string{"accessToken": token}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request payload"})
			return
		}

		// Make a POST request to the authentication server
		req, err := http.NewRequest("POST", "https://localhost:8080/api/userinfo", bytes.NewBuffer(payloadBytes))
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create POST request"})
			return
		}
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user information"})
			return
		}
		defer resp.Body.Close()

		// Handle non-200 response status codes
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body) // Safely read response body
			context.JSON(resp.StatusCode, gin.H{"error": string(body)})
			return
		}

		// Decode user information from the response
		var userInfo map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user information"})
			return
		}

		// Display user information on the sample site
		context.HTML(http.StatusOK, "profile.html", gin.H{
			"title":       "User Profile",
			"userInfo":    userInfo,
			"accessToken": token, // Store the token if needed for API calls
		})
	})
	router.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusOK, "index.html", nil)
	})

	err := router.RunTLS(":4040", "./service/certificates/server.crt", "./service/certificates/server.key")
	if err != nil {
		return
	}
}
