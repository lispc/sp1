package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/succinctlabs/sp1-recursion-groth16/babybear"
	"github.com/succinctlabs/sp1-recursion-groth16/unsafekzg"
)

func TestMain(t *testing.T) {
	// Get the file name from an environment variable.
	fileName := os.Getenv("WITNESS_JSON")
	if fileName == "" {
		fileName = "witness.json"
	}

	// Read the file.
	data, err := os.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	// Deserialize the JSON data into a slice of Instruction structs
	var witness Witness
	err = json.Unmarshal(data, &witness)
	if err != nil {
		panic(err)
	}

	vars := make([]frontend.Variable, len(witness.Vars))
	felts := make([]*babybear.Variable, len(witness.Felts))
	exts := make([]*babybear.ExtensionVariable, len(witness.Exts))
	for i := 0; i < len(witness.Vars); i++ {
		vars[i] = frontend.Variable(witness.Vars[i])
	}
	for i := 0; i < len(witness.Felts); i++ {
		felts[i] = babybear.NewF(witness.Felts[i])
	}
	for i := 0; i < len(witness.Exts); i++ {
		exts[i] = babybear.NewE(witness.Exts[i])
	}

	// Run some sanity checks.
	circuit := Circuit{
		Vars:  vars,
		Felts: felts,
		Exts:  exts,
	}

	// Compile the circuit.
	start := time.Now()
	builder := scs.NewBuilder
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	fmt.Printf("compilation took %s\n", elapsed)
	fmt.Println("NbConstraints:", r1cs.GetNbConstraints())

	// Generate the witness.
	start = time.Now()
	witnessFull, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	witnessPublic, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		log.Fatal(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("witness gen took %s\n", elapsed)

	// create the necessary data for KZG.
	// This is a toy example, normally the trusted setup to build ZKG
	// has been run before.
	// The size of the data in KZG should be the closest power of 2 bounding //
	// above max(nbConstraints, nbVariables).
	ccs := r1cs.(*cs.SparseR1CS)
	start = time.Now()
	srs, _, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		panic(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("src generated take %s\n", elapsed)

	// public data consists of the polynomials describing the constants involved
	// in the constraints, the polynomial describing the permutation ("grand
	// product argument"), and the FFT domains.
	start = time.Now()
	pk, vk, err := plonk.Setup(ccs, srs)
	elapsed = time.Since(start)
	//_, err := plonk.Setup(r1cs, kate, &publicWitness)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("setup done %s\n", elapsed)

	start = time.Now()
	proof, err := plonk.Prove(ccs, pk, witnessFull)
	if err != nil {
		log.Fatal(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("prove done %s\n", elapsed)

	start = time.Now()
	err = plonk.Verify(proof, vk, witnessPublic)
	if err != nil {
		log.Fatal(err)
	}
	elapsed = time.Since(start)
	fmt.Printf("verify done %s\n", elapsed)
}
