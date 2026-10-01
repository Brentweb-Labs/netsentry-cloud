import { Injectable, OnDestroy } from '@angular/core';
import { Subject } from 'rxjs';
import { AuthService } from './auth.service';

export interface LiveMessage {
  type: string;
  [key: string]: unknown;
}

/** Tenant-scoped live feed (alerts, block changes, telemetry) over /ws. */
@Injectable({ providedIn: 'root' })
export class LiveFeed implements OnDestroy {
  readonly messages$ = new Subject<LiveMessage>();
  private socket?: WebSocket;
  private retry?: ReturnType<typeof setTimeout>;
  private wanted = false;
  private refs = 0;

  constructor(private auth: AuthService) {}

  /** Reference-counted: connect on first subscriber, close when the last leaves. */
  acquire(): () => void {
    this.refs++;
    this.wanted = true;
    this.connect();
    return () => {
      this.refs = Math.max(0, this.refs - 1);
      if (this.refs === 0) this.close();
    };
  }

  private connect() {
    if (this.socket && this.socket.readyState <= WebSocket.OPEN) return;
    const token = this.auth.getToken();
    if (!token) return;
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${scheme}://${location.host}/ws?token=${encodeURIComponent(token)}`);
    this.socket = socket;
    socket.onmessage = (ev) => {
      try {
        this.messages$.next(JSON.parse(ev.data as string) as LiveMessage);
      } catch {
        /* ignore malformed frames */
      }
    };
    socket.onclose = () => {
      this.socket = undefined;
      if (this.wanted) this.retry = setTimeout(() => this.connect(), 3000);
    };
  }

  private close() {
    this.wanted = false;
    clearTimeout(this.retry);
    this.socket?.close();
    this.socket = undefined;
  }

  ngOnDestroy() {
    this.close();
  }
}
