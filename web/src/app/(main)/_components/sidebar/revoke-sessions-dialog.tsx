"use client";

import { type FormEvent, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";

export function RevokeSessionsDialog({
  onClose,
  onSuccess,
}: {
  readonly onClose: () => void;
  readonly onSuccess: () => void;
}) {
  const [password, setPassword] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!password || pending) return;
    setError("");
    setPending(true);
    try {
      await api.revokeSessions(password);
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not sign out sessions. Try again.");
      setPending(false);
    }
  }

  return (
    <Dialog open onOpenChange={(open) => !open && !pending && onClose()}>
      <DialogContent className="sm:max-w-md">
        <form onSubmit={submit}>
          <DialogHeader>
            <DialogTitle>Sign out everywhere</DialogTitle>
            <DialogDescription>
              This signs out this device and revokes existing ARTEX session tokens on other devices and clients. Enter
              your password to confirm.
            </DialogDescription>
          </DialogHeader>
          <div className="flex flex-col gap-1.5 py-4">
            <Label htmlFor="revoke-sessions-password">Current password</Label>
            <Input
              id="revoke-sessions-password"
              type="password"
              autoComplete="current-password"
              required
              disabled={pending}
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            {error && (
              <p className="text-destructive text-sm" role="alert">
                {error}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={pending}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={!password || pending}>
              {pending ? "Signing out…" : "Sign out everywhere"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
