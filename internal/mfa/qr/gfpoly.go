// Derived from github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc,
// utils/gfpoly.go. Trimmed to what this package uses (byte-mode, error-correction
// level M, automatic version) and modified; see LICENSE in this directory.
// Copyright (c) 2014 Florian Sundermann.
// SPDX-License-Identifier: MIT

package qr

type gfPoly struct {
	gf           *galoisField
	Coefficients []int
}

func (gp *gfPoly) Degree() int {
	return len(gp.Coefficients) - 1
}

func (gp *gfPoly) Zero() bool {
	return gp.Coefficients[0] == 0
}

// GetCoefficient returns the coefficient of x ^ degree
func (gp *gfPoly) GetCoefficient(degree int) int {
	return gp.Coefficients[gp.Degree()-degree]
}

func (gp *gfPoly) AddOrSubstract(other *gfPoly) *gfPoly {
	if gp.Zero() {
		return other
	} else if other.Zero() {
		return gp
	}
	smallCoeff := gp.Coefficients
	largeCoeff := other.Coefficients
	if len(smallCoeff) > len(largeCoeff) {
		largeCoeff, smallCoeff = smallCoeff, largeCoeff
	}
	sumDiff := make([]int, len(largeCoeff))
	lenDiff := len(largeCoeff) - len(smallCoeff)
	copy(sumDiff, largeCoeff[:lenDiff])
	for i := lenDiff; i < len(largeCoeff); i++ {
		sumDiff[i] = int(gp.gf.AddOrSub(int(smallCoeff[i-lenDiff]), int(largeCoeff[i])))
	}
	return newGFPoly(gp.gf, sumDiff)
}

func (gp *gfPoly) MultByMonominal(degree int, coeff int) *gfPoly {
	if coeff == 0 {
		return gp.gf.Zero()
	}
	size := len(gp.Coefficients)
	result := make([]int, size+degree)
	for i := 0; i < size; i++ {
		result[i] = int(gp.gf.Multiply(int(gp.Coefficients[i]), int(coeff)))
	}
	return newGFPoly(gp.gf, result)
}

func (gp *gfPoly) Multiply(other *gfPoly) *gfPoly {
	if gp.Zero() || other.Zero() {
		return gp.gf.Zero()
	}
	aCoeff := gp.Coefficients
	aLen := len(aCoeff)
	bCoeff := other.Coefficients
	bLen := len(bCoeff)
	product := make([]int, aLen+bLen-1)
	for i := 0; i < aLen; i++ {
		ac := int(aCoeff[i])
		for j := 0; j < bLen; j++ {
			bc := int(bCoeff[j])
			product[i+j] = int(gp.gf.AddOrSub(int(product[i+j]), gp.gf.Multiply(ac, bc)))
		}
	}
	return newGFPoly(gp.gf, product)
}

func (gp *gfPoly) Divide(other *gfPoly) (quotient *gfPoly, remainder *gfPoly) {
	quotient = gp.gf.Zero()
	remainder = gp
	fld := gp.gf
	denomLeadTerm := other.GetCoefficient(other.Degree())
	inversDenomLeadTerm := fld.Invers(int(denomLeadTerm))
	for remainder.Degree() >= other.Degree() && !remainder.Zero() {
		degreeDiff := remainder.Degree() - other.Degree()
		scale := int(fld.Multiply(int(remainder.GetCoefficient(remainder.Degree())), inversDenomLeadTerm))
		term := other.MultByMonominal(degreeDiff, scale)
		itQuot := newMonominalPoly(fld, degreeDiff, scale)
		quotient = quotient.AddOrSubstract(itQuot)
		remainder = remainder.AddOrSubstract(term)
	}
	return
}

func newMonominalPoly(field *galoisField, degree int, coeff int) *gfPoly {
	if coeff == 0 {
		return field.Zero()
	}
	result := make([]int, degree+1)
	result[0] = coeff
	return newGFPoly(field, result)
}

func newGFPoly(field *galoisField, coefficients []int) *gfPoly {
	for len(coefficients) > 1 && coefficients[0] == 0 {
		coefficients = coefficients[1:]
	}
	return &gfPoly{field, coefficients}
}
