package worker

import (
	"Third-Party-Multi-Factor-Authentication-System/db"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/mongo"
)

type RedisTaskProcessor struct {
	Server *asynq.Server
	Store  *db.Store
}

func NewRedisTaskProcessor(opt *asynq.RedisClientOpt, store *db.Store) *RedisTaskProcessor {
	server := asynq.NewServer(opt, asynq.Config{})

	return &RedisTaskProcessor{
		Server: server,
		Store:  store,
	}
}

func (p *RedisTaskProcessor) ProcessSendVerificationEmail(ctx context.Context, task *asynq.Task) error {
	var payload *SendVerificationEmailPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("failed to unmarshal payload: %w", asynq.SkipRetry)
	}

	_, err := p.Store.GetUserByUsernameAndPassword(payload.Username, "")
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return fmt.Errorf("user does not exists: %w", asynq.SkipRetry)
		}
		return fmt.Errorf("failed to get user from database: %w", err)
	}

	fmt.Println("send verification message")

	return nil
}

func (p *RedisTaskProcessor) Start() error {
	mux := asynq.NewServeMux()

	mux.HandleFunc(TaskSendVerificationEmail, p.ProcessSendVerificationEmail)

	return p.Server.Start(mux)
}
