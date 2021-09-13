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
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/go-redis/redis/v8"
)

var ctx = context.Background()

type LoginInfo struct {
	UserToken string `json:"userToken"`
}

func verifyLoginFromRedis(loginMsg *msg.Login) (errInfo error) {

	if len(loginMsg.User) == 0 {
		return errors.New("user are empty please add user=<useryour> to your frpc.ini in section [common]")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password set
		DB:       0,  // use default DB
	})
	finalUserKey := fmt.Sprintf("%s:%s", "FRPC", loginMsg.User)

	val, err := rdb.Get(ctx, finalUserKey).Result()
	if err != nil {
		message := fmt.Sprintf("Not able to get user with key: %s %s", finalUserKey, err.Error())
		return errors.New(message)
	}
	var loginInfo LoginInfo
	json.Unmarshal([]byte(val), &loginInfo)

	storedKey := util.GetAuthKey(loginInfo.UserToken, loginMsg.Timestamp)
	clientKey := loginMsg.PrivilegeKey

	if storedKey != clientKey {
		//var message string
		message := fmt.Sprintf("The key stored %s is not match with sent priv key %s\n", storedKey, clientKey)
		return errors.New(message)
	}

	return nil
}

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

	//fmt.Println("Tryint to get metas")
	for key, value := range loginMsg.Metas {
		fmt.Printf("%s = %s\n", key, value)

	}
	err := verifyLoginFromRedis(loginMsg)
	if err != nil {
		return fmt.Errorf(err.Error())
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
