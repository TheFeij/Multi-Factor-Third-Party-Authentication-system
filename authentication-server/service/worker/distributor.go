package worker

import "github.com/hibiken/asynq"

type RedisTaskDistributor struct {
	client *asynq.Client
}

func NewRedisTaskDistributor(opt *asynq.RedisClientOpt) *RedisTaskDistributor {
	return &RedisTaskDistributor{client: asynq.NewClient(opt)}
}
