package main

import (
	"fmt"
	"math"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	// 암호화되지 않은 바이트 배열 생성.
	plainPws := func() [][]byte {
		var plainPws [][]byte
		for alphabet := ' '; alphabet <= 'z'; alphabet++ {
			var sentense string
			for i := 0; i < 3; i++ {
				sentense = string(alphabet) + string(alphabet) + string(alphabet)
			}
			plainPws = append(plainPws, []byte(sentense))
		}
		return plainPws
	}()
	startTime := time.Now()
	// 암호화 되지 않았던 바이트 배열 암호화.
	encryptedPws, err := encrypt(plainPws)
	if err != nil {
		fmt.Printf("encrypt err %v", err)
		return
	}
	// 암호화된 바이트 배열 검증.
	if err = validateEncryptedPw(plainPws, encryptedPws); err != nil {
		fmt.Printf("password validation failed %v", err)
		return
	}
	result := fmt.Sprintf("using Serialize - total %v, excuted time %v", len(plainPws), time.Since(startTime))
	fmt.Println("----------------------------")

	startTime = time.Now()
	ch := make(chan bool)
	// 동시성 처리를 위한 데이터 구조 변경.
	dividedPlainPw := getDividedPlainPws(plainPws)
	var total [][]byte

	for i := 0; i < len(dividedPlainPw); i++ {
		// 변경된 데이터 구조 길이만큼 고루틴 생성하여 처리.
		go func(idx int) {
			encryptedPws, err := encrypt(dividedPlainPw[idx])
			if err != nil {
				fmt.Printf("encrypt err %v", err)
				return
			}
			if err = validateEncryptedPw(dividedPlainPw[idx], encryptedPws); err != nil {
				fmt.Printf("password validation failed %v", err)
				return
			}
			total = append(total, encryptedPws...)
			ch <- true
		}(i)
	}
	// 생성된 모든 고루틴 완료까지 대기.
	for i := 0; i < len(dividedPlainPw); i++ {
		<-ch
	}

	result += fmt.Sprintf("\nusing Concurrency - total %v, excuted time %v", len(total), time.Since(startTime))
	fmt.Printf("%v\n", result)
}

// 평문 바이트 배열을 매개변수로 받아 암호화하여 결과 및 에러 리턴.
func encrypt(plainPws [][]byte) ([][]byte, error) {
	var encryptedPws [][]byte
	for _, plainPw := range plainPws {
		encryptedPassword, err := bcrypt.GenerateFromPassword(plainPw, bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		encryptedPws = append(encryptedPws, encryptedPassword)
	}
	return encryptedPws, nil
}

// 평문 바이트 배열과 암호화된 바이트 배열 비교 -> 제대로 생성 혹은 부합하는지 확인하여
// 에러 리턴
func validateEncryptedPw(plainPws [][]byte, encryptedPws [][]byte) error {
	var sentense string
	for idx, _ := range plainPws {
		sentense = fmt.Sprintf("%v %v", string(plainPws[idx]), string(encryptedPws[idx]))
		if err := bcrypt.CompareHashAndPassword(encryptedPws[idx], plainPws[idx]); err != nil {
			fmt.Printf("%v failed\n", sentense)
			return err
		}
		fmt.Printf("%v success\n", sentense)
	}
	return nil
}

// 평문 바이트 배열을 임의로 선정한 변수(jobLength)에 따라 데이터 구조 변경하는 함수
// jobLength의 경우 하드코딩되어 있음.
func getDividedPlainPws(plainPws [][]byte) [][][]byte {
	jobLength := 2
	var dividedPlainPw [][][]byte
	for i := 0; i <= int(math.Ceil(float64(len(plainPws)/jobLength))); i++ {
		startIdx, endIdx := i*jobLength, i*jobLength+jobLength
		idx := -1
		for index, value := range plainPws[startIdx:endIdx] {
			if value == nil {
				idx = index
				break
			}
		}
		if idx == -1 {
			dividedPlainPw = append(dividedPlainPw, plainPws[startIdx:endIdx])
		} else {
			dividedPlainPw = append(dividedPlainPw, plainPws[startIdx:startIdx+idx])
		}
	}
	return dividedPlainPw
}
