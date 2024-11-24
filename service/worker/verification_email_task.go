package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hibiken/asynq"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const TaskSendVerificationEmail = "task:send_verification_email"

type SendVerificationEmailPayload struct {
	ID primitive.ObjectID `json:"id,omitempty"`
}

func (r *RedisTaskDistributor) SendVerificationEmail(
	ctx context.Context,
	payload *SendVerificationEmailPayload,
	opt ...asynq.Option,
) error {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to unmarshal the payload into byte slice %w", err)
	}

	task := asynq.NewTask(TaskSendVerificationEmail, jsonPayload, opt...)

	taskInfo, err := r.client.EnqueueContext(ctx, task)
	if err != nil {
		return fmt.Errorf("failed to enqueue task %w", err)
	}

	fmt.Println(taskInfo.MaxRetry)

	return nil
}
