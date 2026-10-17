package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/parkerbrown98/gotalk-gateway/internal/blocklist"
	"github.com/parkerbrown98/gotalk-gateway/internal/config"
	"github.com/parkerbrown98/gotalk-gateway/internal/instances"
	"github.com/parkerbrown98/gotalk-gateway/internal/store"
	"github.com/parkerbrown98/gotalk-gateway/internal/wellknown"
)

func when(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func instancesCmd(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, f adminFlags, out io.Writer) error {
	pool, err := connectDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	fetcher := wellknown.New(wellknown.Options{AllowPrivateNetworks: cfg.Instances.AllowPrivateNetworks, AllowedPorts: cfg.Instances.AllowedPorts})
	svc := instances.New(pool, fetcher, blocklist.NewCache(pool, log), instances.Options{AllowHTTP: cfg.Instances.AllowHTTP, Logger: log})

	sub, target := args[0], ""
	if len(args) > 1 {
		target = args[1]
	}
	if sub != "list" && target == "" {
		return fmt.Errorf("instances %s needs an instance ID or origin", sub)
	}

	switch sub {
	case "list":
		if target != "" {
			return fmt.Errorf("unexpected argument %q", target)
		}
		list, err := svc.List(ctx, f.status, f.limit)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ID\tORIGIN\tSTATUS\tVERIFIED\tCREATED")
		for _, i := range list {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.ID, i.Origin, i.Status, when(i.VerifiedAt), when(&i.CreatedAt))
		}
		return tw.Flush()

	case "show":
		found, err := svc.Find(ctx, target)
		if err != nil {
			return err
		}
		if len(found) == 0 {
			return errors.New("no such instance")
		}
		for n, i := range found {
			v, err := svc.View(ctx, i.ID)
			if err != nil {
				return err
			}
			if n > 0 {
				_, _ = fmt.Fprintln(out)
			}
			printInstance(out, v)
		}
		return nil

	case "block", "unblock", "delete":
		inst, err := resolveOne(ctx, svc, target)
		if err != nil {
			return err
		}
		switch sub {
		case "block":
			if err := svc.Block(ctx, inst.ID, f.reason); err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "blocked %s (%s)\n", inst.ID, inst.Origin)
			return err
		case "unblock":
			if err := svc.Unblock(ctx, inst.ID); err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "unblocked %s (%s); it will be re-verified within a minute\n", inst.ID, inst.Origin)
			return err
		default:
			if !f.yes {
				return fmt.Errorf("this deletes %s (%s) and all its subscriptions; repeat with --yes", inst.ID, inst.Origin)
			}
			if err := svc.Delete(ctx, inst.ID); err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "deleted %s (%s)\n", inst.ID, inst.Origin)
			return err
		}
	default:
		return fmt.Errorf("unknown instances subcommand %q", sub)
	}
}

// resolveOne finds the single instance meant by an ID or origin, preferring the verified
// instance of an origin over its pending registrations.
func resolveOne(ctx context.Context, svc *instances.Service, target string) (store.Instance, error) {
	found, err := svc.Find(ctx, target)
	if err != nil {
		return store.Instance{}, err
	}
	var verified []store.Instance
	for _, i := range found {
		if i.Status != instances.StatusPending {
			verified = append(verified, i)
		}
	}
	switch {
	case len(verified) == 1:
		return verified[0], nil
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0:
		return store.Instance{}, errors.New("no such instance")
	}
	ids := make([]string, len(found))
	for i, inst := range found {
		ids[i] = inst.ID
	}
	return store.Instance{}, fmt.Errorf("%s matches several pending registrations (%s); use an instance ID", target, strings.Join(ids, ", "))
}

func printInstance(out io.Writer, v *instances.View) {
	i := v.Instance
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	row := func(k, val string) { _, _ = fmt.Fprintf(tw, "%s:\t%s\n", k, val) }
	row("ID", i.ID)
	row("Origin", i.Origin)
	row("Status", i.Status)
	if r := v.StatusReason(); r != nil {
		row("Reason", *r)
	}
	row("Contact", i.ContactEmail)
	if i.Software != nil {
		row("Software", strings.TrimSpace(*i.Software+" "+deref(i.SoftwareVersion)))
	}
	row("Created", when(&i.CreatedAt))
	row("Verified", when(i.VerifiedAt))
	row("Last verified", when(i.LastVerifiedAt))
	if i.Status == instances.StatusPending {
		row("Expires", when(i.PendingExpiresAt))
	} else {
		row("Next verification", when(i.NextVerificationAt))
		row("Failed verifications", fmt.Sprint(i.VerificationFailures))
	}
	row("Usage today", fmt.Sprintf("%d accepted, %d failed, %d active subscriptions",
		v.Usage.PushesAccepted, v.Usage.PushesFailed, v.Usage.ActiveSubscriptions))
	_ = tw.Flush()

	_, _ = fmt.Fprintln(out, "Keys:")
	tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "  ID\tSTATUS\tPUBLIC KEY\tCREATED\tLAST USED")
	for _, k := range v.Keys {
		status := k.Status
		if k.Recovery {
			status += " (recovery)"
		}
		_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", k.ID, status, instances.EncodeKey(k.PublicKey), when(&k.CreatedAt), when(k.LastUsedAt))
	}
	_ = tw.Flush()
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func blocklistCmd(ctx context.Context, cfg *config.Config, log *slog.Logger, args []string, f adminFlags, out io.Writer) error {
	pool, err := connectDatabase(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer pool.Close()
	q := store.New(pool)

	normalize := func() (kind, value string, err error) {
		if len(args) != 3 {
			return "", "", fmt.Errorf("blocklist %s needs KIND VALUE", args[0])
		}
		kind, value = args[1], args[2]
		if kind == blocklist.KindOrigin {
			if value, err = instances.NormalizeOrigin(value, true); err != nil {
				return "", "", fmt.Errorf("origin %w", err)
			}
		}
		value, err = blocklist.NormalizeValue(kind, value)
		return kind, value, err
	}

	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("unexpected argument %q", args[1])
		}
		entries, err := q.ListBlocklist(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "KIND\tVALUE\tEXPIRES\tREASON")
		for _, e := range entries {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.Kind, e.Value, when(e.ExpiresAt), e.Reason)
		}
		return tw.Flush()

	case "add":
		kind, value, err := normalize()
		if err != nil {
			return err
		}
		if strings.TrimSpace(f.reason) == "" {
			return errors.New("--reason is required; it is shown to whoever is blocked")
		}
		var expires *time.Time
		if f.expires < 0 {
			return errors.New("--expires must be positive")
		} else if f.expires > 0 {
			t := time.Now().Add(f.expires)
			expires = &t
		}
		e, err := q.UpsertBlocklistEntry(ctx, store.UpsertBlocklistEntryParams{Kind: kind, Value: value, Reason: f.reason, ExpiresAt: expires})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "blocked %s %s (expires %s); running gateways apply it within %s\n",
			e.Kind, e.Value, when(e.ExpiresAt), blocklist.RefreshInterval)
		return err

	case "remove":
		kind, value, err := normalize()
		if err != nil {
			return err
		}
		n, err := q.DeleteBlocklistEntry(ctx, store.DeleteBlocklistEntryParams{Kind: kind, Value: value})
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("no blocklist entry %s %s", kind, value)
		}
		_, err = fmt.Fprintf(out, "removed %s %s\n", kind, value)
		return err

	default:
		return fmt.Errorf("unknown blocklist subcommand %q", args[0])
	}
}
