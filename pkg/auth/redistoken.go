// Copyright 2020 guylewin, guy@lewin.co.il
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

var ctx = context.Background()

/*
func verifyFromRedis(clientToken string) (err error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	err := rdb.Set(ctx, clientToken, 111, 0).Err()
	if err != nil {
		panic(err)
	}

	val, err := rdb.Get(ctx, clientToken).Result()
	if err != nil {
		panic(err)
	}

	return nil
}
*/
/*
type TokenConfig struct {
	// Token specifies the authorization token used to create keys to be sent
	// to the server. The server must have a matching token for authorization
	// to succeed.  By default, this value is "".
	Token string `ini:"token" json:"token"`
}

func getDefaultTokenConf() TokenConfig {
	return TokenConfig{
		Token: "",
	}
}
*/
type RedisTokenAuthSetterVerifier struct {
	BaseConfig

	token string
}

func NewRedisTokenAuth(baseCfg BaseConfig, cfg TokenConfig) *RedisTokenAuthSetterVerifier {
	return &RedisTokenAuthSetterVerifier{
		BaseConfig: baseCfg,
		token:      cfg.Token,
	}
}

func (auth *RedisTokenAuthSetterVerifier) SetLogin(loginMsg *msg.Login) (err error) {
	loginMsg.PrivilegeKey = util.GetAuthKey(auth.token, loginMsg.Timestamp)
	return nil
}

func (auth *RedisTokenAuthSetterVerifier) SetPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	pingMsg.Timestamp = time.Now().Unix()
	pingMsg.PrivilegeKey = util.GetAuthKey(auth.token, pingMsg.Timestamp)
	return nil
}

func (auth *RedisTokenAuthSetterVerifier) SetNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	newWorkConnMsg.Timestamp = time.Now().Unix()
	newWorkConnMsg.PrivilegeKey = util.GetAuthKey(auth.token, newWorkConnMsg.Timestamp)
	return nil
}

func (auth *RedisTokenAuthSetterVerifier) VerifyLogin(loginMsg *msg.Login) error {

	fmt.Println("Tryint to get metas")
	for key, value := range loginMsg.Metas {
		fmt.Printf("%s = %s\n", key, value)

	}

	if util.GetAuthKey(auth.token, loginMsg.Timestamp) != loginMsg.PrivilegeKey {
		return fmt.Errorf(
			"token in login doesn't match token from configuration by redis ====>user" +
				loginMsg.User + " key:" + loginMsg.PrivilegeKey)
	}
	return nil
}

func (auth *RedisTokenAuthSetterVerifier) VerifyPing(pingMsg *msg.Ping) error {
	if !auth.AuthenticateHeartBeats {
		return nil
	}

	if util.GetAuthKey(auth.token, pingMsg.Timestamp) != pingMsg.PrivilegeKey {
		return fmt.Errorf("token in heartbeat doesn't match token from configuration by redis")
	}
	return nil
}

func (auth *RedisTokenAuthSetterVerifier) VerifyNewWorkConn(newWorkConnMsg *msg.NewWorkConn) error {
	if !auth.AuthenticateNewWorkConns {
		return nil
	}

	if util.GetAuthKey(auth.token, newWorkConnMsg.Timestamp) != newWorkConnMsg.PrivilegeKey {
		return fmt.Errorf("token in NewWorkConn doesn't match token from configuration by redis")
	}
	return nil
}
