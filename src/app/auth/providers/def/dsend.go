package def

// Sender defines interface to send emails
type Sender interface {
	Send(address, text string) error
}

// SenderFunc type is an adapter to allow the use of ordinary functions as Sender.
type SenderFunc func(address, text string) error

// Send calls f(address,text) to implement Sender interface
func (f SenderFunc) Send(address, text string) error {
	return f(address, text)
}
