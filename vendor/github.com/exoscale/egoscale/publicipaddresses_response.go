// code generated; DO NOT EDIT.

package egoscale

import "fmt"

// Response returns the struct to unmarshal
func (ListPublicIPAddresses) Response() interface{} {
	return new(ListPublicIPAddressesResponse)
}

// ListRequest returns itself
func (ls *ListPublicIPAddresses) ListRequest() (ListCommand, error) {
	if ls == nil {
		return nil, fmt.Errorf("%T cannot be nil", ls)
	}
	return ls, nil
}

// SetPage sets the current apge
func (ls *ListPublicIPAddresses) SetPage(page int) {
	ls.Page = page
}

// SetPageSize sets the page size
func (ls *ListPublicIPAddresses) SetPageSize(pageSize int) {
	ls.PageSize = pageSize
}

// Each triggers the callback for each, valid answer or any non 404 issue
func (ListPublicIPAddresses) Each(resp interface{}, callback IterateItemFunc) {
	items, ok := resp.(*ListPublicIPAddressesResponse)
	if !ok {
		callback(nil, fmt.Errorf("wrong type, ListPublicIPAddressesResponse was expected, got %T", resp))
		return
	}

	for i := range items.PublicIPAddress {
		if !callback(&items.PublicIPAddress[i], nil) {
			break
		}
	}
}
