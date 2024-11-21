package util

import (
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

const (
	LOWERCASE    = "abcdefghijklmnopqrstuvwxyz"
	UPPERCASE    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	NUMBERS      = "0123456789"
	SPECIALS     = "_!@#$%&*^"
	ALPHANUMERIC = LOWERCASE + UPPERCASE + NUMBERS
	ALPHABETS    = LOWERCASE + UPPERCASE
	ALL          = ALPHANUMERIC + SPECIALS
)

var random *rand.Rand

func init() {
	random = rand.New(rand.NewSource(time.Now().UnixNano()))
}

func RandomInt(min int64, max int64) int64 {
	return random.Int63n(max-min+1) + min
}

func RandomString(length int, alphabet string) string {
	alphabetLength := len(alphabet)
	var randomString strings.Builder

	for i := 0; i < length; i++ {
		randomByte := alphabet[random.Intn(alphabetLength)]
		randomString.WriteByte(randomByte)
	}

	return randomString.String()
}

func RandomID() int64 {
	return RandomInt(1, math.MaxInt64)
}

func RandomUsername() string {
	username := RandomString(1, ALPHABETS)
	username += RandomString(
		int(RandomInt(3, 62)),
		ALPHANUMERIC+"_")
	username += RandomString(
		int(RandomInt(0, 1)),
		ALPHANUMERIC)

	return username
}

func RandomPassword() string {
	password := RandomString(1, LOWERCASE)
	password += RandomString(1, UPPERCASE)
	password += RandomString(1, NUMBERS)
	password += RandomString(1, SPECIALS)
	password += RandomString(
		int(RandomInt(4, 60)),
		ALL)

	return password
}

func RandomBalance() int64 {
	return RandomInt(0, math.MaxInt64-1)
}

func RandomAmount() int32 {
	return int32(RandomInt(0, math.MinInt32))
}

func RandomFullname() string {
	randomString := RandomString(int(RandomInt(3, 64)), ALPHABETS)

	index := RandomInt(1, int64(len(randomString)-2))
	fullname := randomString[:index]
	fullname += " "
	fullname += randomString[index+1:]

	return fullname
}

func RandomEmail() string {
	username := RandomUsername()
	domain := RandomString(int(RandomInt(5, 10)), ALPHABETS)
	tld := RandomString(int(RandomInt(2, 5)), LOWERCASE)

	return username + "@" + domain + "." + tld
}

func RandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d\n",
		RandomInt(0, 255),
		RandomInt(0, 255),
		RandomInt(0, 255),
		RandomInt(0, 255),
	)
}
