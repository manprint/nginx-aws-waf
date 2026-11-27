package awsexport

import "errors"

// HCL renders the document as Terraform (6.3).
func HCL(d *Document, region string) ([]byte, error) {
	return nil, errors.New("export-aws --format terraform: not implemented yet")
}
