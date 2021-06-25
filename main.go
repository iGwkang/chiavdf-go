package main

import (
	"crypto/rand"
	"fmt"
	chiavdf "github.com/iGwkang/chiavdf-go/chiavdf/go_bindings"
	"log"
	"time"
)

func main() {
	discriminant_challenge := make([]byte, 10)
	_, err := rand.Read(discriminant_challenge)
	if err != nil {
		log.Fatalln(err)
	}
	form_size := chiavdf.BQFC_FORM_SIZE
	discriminant_size := uint64(512)
	discriminant := chiavdf.CreateDiscriminant(discriminant_challenge, discriminant_size)

	initial_el := make([]byte, form_size)
	initial_el[0] = 0x08

	iters := uint64(1000000)
	t1 := time.Now()
	result := chiavdf.Prove(discriminant_challenge, initial_el, discriminant_size, iters)
	t2 := time.Now()
	fmt.Println("IPS: ", iters/uint64(t2.Sub(t1).Milliseconds()), "ms")

	result_y := result[:form_size]
	proof := result[form_size : 2*form_size]

	is_valid := chiavdf.VerifyWesolowski(
		discriminant,
		initial_el,
		result_y,
		proof,
		iters,
	)

	fmt.Println("is valid ", is_valid)

}
