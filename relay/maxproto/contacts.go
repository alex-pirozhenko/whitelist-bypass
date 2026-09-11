package maxproto

import (
	"context"
	"errors"
	"fmt"
)

// Contact opcodes, from the web.max.ru bundle (reference implementation):
//   op41 CONTACT_ADD_BY_PHONE {phone,firstName?,lastName?} -> {contact:{id,...},new}
//   op34 CONTACT_ACTION       {contactId,action}          -> {contact:{...}?}
// op41 both RESOLVES a phone to a uid AND adds the contact in one call — unlike
// op46 (RESOLVE_UID_BY_PHONE), which only resolves numbers that are ALREADY
// contacts (it returns contact.not.found otherwise, even for one's own number).
// So op41 is the primitive for learning a not-yet-contact account's uid, which
// is what roomd/an offerer needs to op76-invite a joiner leg.
const (
	opContactAddByPhone = 41
	opContactAction     = 34
)

// ContactAddByPhone resolves phone to a MAX uid and adds it as a contact
// (op41). firstName/lastName are optional (pass "" to omit). Returns the
// contact's uid and whether it was newly added. Server error codes include
// user.not.found (phone not on MAX), error.add.self, error.invalid-phone.
func (c *Client) ContactAddByPhone(ctx context.Context, phone, firstName, lastName string) (contactID int64, isNew bool, err error) {
	payload := map[string]any{"phone": phone}
	if firstName != "" {
		payload["firstName"] = firstName
	}
	if lastName != "" {
		payload["lastName"] = lastName
	}
	resp, err := c.Cmd(ctx, opContactAddByPhone, payload)
	if err != nil {
		return 0, false, err
	}
	return parseContact(resp)
}

// ContactAction mutates an already-known contact relationship by uid (op34).
// action is one of ADD, UPDATE, REMOVE, BLOCK, UNBLOCK (firstName/lastName are
// only meaningful for UPDATE).
func (c *Client) ContactAction(ctx context.Context, contactID int64, action, firstName, lastName string) error {
	payload := map[string]any{"contactId": contactID, "action": action}
	if action == "UPDATE" {
		if firstName != "" {
			payload["firstName"] = firstName
		}
		if lastName != "" {
			payload["lastName"] = lastName
		}
	}
	_, err := c.Cmd(ctx, opContactAction, payload)
	return err
}

// parseContact pulls {contact:{id}, new} out of an op41 response.
func parseContact(resp any) (contactID int64, isNew bool, err error) {
	m, ok := resp.(map[string]any)
	if !ok {
		return 0, false, fmt.Errorf("unexpected ContactAddByPhone response type: %T", resp)
	}
	contact, ok := m["contact"].(map[string]any)
	if !ok {
		return 0, false, errors.New("contact field missing in ContactAddByPhone response")
	}
	id, ok := toInt64(contact["id"])
	if !ok || id == 0 {
		return 0, false, fmt.Errorf("contact id missing/invalid: %v", contact["id"])
	}
	isNew, _ = m["new"].(bool)
	return id, isNew, nil
}
