package main

import (
	"github.com/consensys/gnark/frontend"
	gnarkposeidon "github.com/mdehoog/poseidon/circuits/poseidon"
)

const (
	merkleTreeDepth = 32
	maxLeaves       = 4
	relationValues  = 24

	commitmentDomain = 101
	nullifierDomain  = 211
	scopeDomain      = 307
	relationDomain   = 503
	aggregateDomain  = 601
)

type BraidOperationCircuit struct {
	Operation        frontend.Variable `gnark:",public"`
	Root             frontend.Variable `gnark:",public"`
	OutputCommitment frontend.Variable `gnark:",public"`
	Nullifier        frontend.Variable `gnark:",public"`

	RelationDigest frontend.Variable
	PredicateMin   frontend.Variable
	PredicateMax   frontend.Variable

	OutputSubject  frontend.Variable
	OutputSecret   frontend.Variable
	Scope          frontend.Variable
	PredicateValue frontend.Variable

	RelationValues [relationValues]frontend.Variable
	LeafSubjects   [maxLeaves]frontend.Variable
	LeafSecrets    [maxLeaves]frontend.Variable
	LeafEnabled    [maxLeaves]frontend.Variable
	PathElements   [maxLeaves][merkleTreeDepth]frontend.Variable
	PathIndices    [maxLeaves][merkleTreeDepth]frontend.Variable
}

type BraidOperationCircuitLeaf0 struct {
	BraidOperationCircuit
}

type BraidOperationCircuitLeaf1 struct {
	BraidOperationCircuit
	LeafCommitment0 frontend.Variable `gnark:",public"`
}

type BraidOperationCircuitLeaf2 struct {
	BraidOperationCircuit
	LeafCommitment0 frontend.Variable `gnark:",public"`
	LeafCommitment1 frontend.Variable `gnark:",public"`
}

type BraidOperationCircuitLeaf3 struct {
	BraidOperationCircuit
	LeafCommitment0 frontend.Variable `gnark:",public"`
	LeafCommitment1 frontend.Variable `gnark:",public"`
	LeafCommitment2 frontend.Variable `gnark:",public"`
}

type BraidOperationCircuitLeaf4 struct {
	BraidOperationCircuit
	LeafCommitment0 frontend.Variable `gnark:",public"`
	LeafCommitment1 frontend.Variable `gnark:",public"`
	LeafCommitment2 frontend.Variable `gnark:",public"`
	LeafCommitment3 frontend.Variable `gnark:",public"`
}

func poseidon2(
	api frontend.API,
	left frontend.Variable,
	right frontend.Variable,
) frontend.Variable {
	return gnarkposeidon.Hash(api, []frontend.Variable{left, right})
}

func commitmentHashCircuit(
	api frontend.API,
	subject frontend.Variable,
	witness frontend.Variable,
) frontend.Variable {
	return poseidon2(api, api.Add(subject, commitmentDomain), witness)
}

func scopedNullifierHashCircuit(
	api frontend.API,
	subject frontend.Variable,
	witness frontend.Variable,
	scope frontend.Variable,
) frontend.Variable {
	scopedSubject := poseidon2(api, api.Add(subject, scopeDomain), scope)
	return poseidon2(api, scopedSubject, api.Add(witness, nullifierDomain))
}

func foldCircuit(
	api frontend.API,
	domain frontend.Variable,
	values []frontend.Variable,
) frontend.Variable {
	accumulator := domain

	for _, value := range values {
		accumulator = poseidon2(api, accumulator, value)
	}

	return accumulator
}

func merkleRootFromProof(
	api frontend.API,
	leaf frontend.Variable,
	pathElements [merkleTreeDepth]frontend.Variable,
	pathIndices [merkleTreeDepth]frontend.Variable,
) frontend.Variable {
	current := leaf

	for level := 0; level < merkleTreeDepth; level++ {
		api.AssertIsBoolean(pathIndices[level])

		left := api.Select(pathIndices[level], pathElements[level], current)
		right := api.Select(pathIndices[level], current, pathElements[level])
		current = poseidon2(api, left, right)
	}

	return current
}

func defineOperationCircuit(
	api frontend.API,
	circuit *BraidOperationCircuit,
	leafCommitments [maxLeaves]frontend.Variable,
	usedLeaves int,
) error {
	outputSubject := foldCircuit(api, 0, circuit.RelationValues[:])
	api.AssertIsEqual(circuit.OutputSubject, outputSubject)

	outputCommitment := commitmentHashCircuit(
		api,
		circuit.OutputSubject,
		circuit.OutputSecret,
	)
	api.AssertIsEqual(circuit.OutputCommitment, outputCommitment)

	outputNullifier := scopedNullifierHashCircuit(
		api,
		circuit.OutputSubject,
		circuit.OutputSecret,
		circuit.Scope,
	)
	nullifier := poseidon2(
		api,
		api.Add(circuit.Operation, aggregateDomain),
		circuit.Scope,
	)
	nullifier = poseidon2(api, nullifier, outputNullifier)

	relationDigest := poseidon2(
		api,
		api.Add(circuit.Operation, relationDomain),
		circuit.Scope,
	)
	relationDigest = poseidon2(api, relationDigest, circuit.OutputSubject)
	relationDigest = poseidon2(api, relationDigest, circuit.OutputSecret)
	relationDigest = poseidon2(api, relationDigest, circuit.PredicateValue)
	relationDigest = poseidon2(api, relationDigest, circuit.PredicateMin)
	relationDigest = poseidon2(api, relationDigest, circuit.PredicateMax)

	for index := 0; index < relationValues; index++ {
		relationDigest = poseidon2(
			api,
			relationDigest,
			circuit.RelationValues[index],
		)
	}

	if usedLeaves == 0 {
		api.AssertIsEqual(circuit.Root, 0)
	} else {
		api.AssertIsEqual(api.IsZero(circuit.Root), 0)
	}

	for index := 0; index < usedLeaves; index++ {
		api.AssertIsBoolean(circuit.LeafEnabled[index])
		api.AssertIsEqual(circuit.LeafEnabled[index], 1)

		leafCommitment := commitmentHashCircuit(
			api,
			circuit.LeafSubjects[index],
			circuit.LeafSecrets[index],
		)
		api.AssertIsEqual(leafCommitments[index], leafCommitment)

		leafRoot := merkleRootFromProof(
			api,
			leafCommitment,
			circuit.PathElements[index],
			circuit.PathIndices[index],
		)
		api.AssertIsEqual(leafRoot, circuit.Root)

		leafNullifier := scopedNullifierHashCircuit(
			api,
			circuit.LeafSubjects[index],
			circuit.LeafSecrets[index],
			circuit.Scope,
		)
		nullifier = poseidon2(
			api,
			nullifier,
			leafNullifier,
		)

		relationDigest = poseidon2(
			api,
			relationDigest,
			circuit.LeafSubjects[index],
		)
		relationDigest = poseidon2(
			api,
			relationDigest,
			leafCommitment,
		)
	}

	for index := usedLeaves; index < maxLeaves; index++ {
		api.AssertIsBoolean(circuit.LeafEnabled[index])
		api.AssertIsEqual(circuit.LeafEnabled[index], 0)
		nullifier = poseidon2(api, nullifier, 0)
		relationDigest = poseidon2(api, relationDigest, 0)
		relationDigest = poseidon2(api, relationDigest, 0)
	}

	minIsZero := api.IsZero(circuit.PredicateMin)
	minBound := api.Select(minIsZero, circuit.PredicateValue, circuit.PredicateMin)
	api.AssertIsLessOrEqual(minBound, circuit.PredicateValue)

	maxIsZero := api.IsZero(circuit.PredicateMax)
	maxBound := api.Select(maxIsZero, circuit.PredicateValue, circuit.PredicateMax)
	api.AssertIsLessOrEqual(circuit.PredicateValue, maxBound)

	api.AssertIsEqual(circuit.Nullifier, nullifier)
	api.AssertIsEqual(circuit.RelationDigest, relationDigest)

	return nil
}

func (circuit *BraidOperationCircuitLeaf0) Define(api frontend.API) error {
	return defineOperationCircuit(
		api,
		&circuit.BraidOperationCircuit,
		[maxLeaves]frontend.Variable{},
		0,
	)
}

func (circuit *BraidOperationCircuitLeaf1) Define(api frontend.API) error {
	return defineOperationCircuit(
		api,
		&circuit.BraidOperationCircuit,
		[maxLeaves]frontend.Variable{
			circuit.LeafCommitment0,
		},
		1,
	)
}

func (circuit *BraidOperationCircuitLeaf2) Define(api frontend.API) error {
	return defineOperationCircuit(
		api,
		&circuit.BraidOperationCircuit,
		[maxLeaves]frontend.Variable{
			circuit.LeafCommitment0,
			circuit.LeafCommitment1,
		},
		2,
	)
}

func (circuit *BraidOperationCircuitLeaf3) Define(api frontend.API) error {
	return defineOperationCircuit(
		api,
		&circuit.BraidOperationCircuit,
		[maxLeaves]frontend.Variable{
			circuit.LeafCommitment0,
			circuit.LeafCommitment1,
			circuit.LeafCommitment2,
		},
		3,
	)
}

func (circuit *BraidOperationCircuitLeaf4) Define(api frontend.API) error {
	return defineOperationCircuit(
		api,
		&circuit.BraidOperationCircuit,
		[maxLeaves]frontend.Variable{
			circuit.LeafCommitment0,
			circuit.LeafCommitment1,
			circuit.LeafCommitment2,
			circuit.LeafCommitment3,
		},
		4,
	)
}
