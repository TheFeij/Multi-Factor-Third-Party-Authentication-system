package cache

import (
	"context"
	"encoding/json"
	"github.com/redis/go-redis/v9"
	"log"
	"mobile-app-server/config"
	"time"
)

// Cache contains a redis client and provides methods to cache and load data
type Cache struct {
	// redisClient a redis.client object
	redisClient *redis.Client
}

// SetData caches json data (map[string]interface) into redis
func (c Cache) SetData(key string, data map[string]interface{}, expiration time.Duration) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}

	ctx := context.Background()
	err = c.redisClient.Set(ctx, key, jsonData, expiration).Err()
	if err != nil {
		return err
	}

	return nil
}

// GetData loads json data (map[string]interface) from cache
func (c Cache) GetData(key string) (map[string]interface{}, error) {
	var result map[string]interface{}

	ctx := context.Background()
	data, err := c.redisClient.Get(ctx, key).Bytes()
	if err != nil {
		return result, err
	}

	err = json.Unmarshal(data, &result)
	if err != nil {
		return result, err
	}

	return result, nil
}

func (c Cache) DeleteData(key string) error {
	ctx := context.Background()
	err := c.redisClient.Del(ctx, key).Err()
	if err != nil {
		return err
	}

	return nil
}

// GetCache returns a cache
func GetCache(configs *config.Config) *Cache {
	cache := &Cache{
		redisClient: redis.NewClient(&redis.Options{
			Addr:        configs.RedisAddress,
			DB:          configs.RedisDB,
			DialTimeout: configs.RedisDialTimeout,
			ReadTimeout: configs.RedisReadTimeout,
		}),
	}

	ctx := context.Background()
	if err := cache.redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("failed to initialize redis:\n%v", err)
	}

	return cache
}
