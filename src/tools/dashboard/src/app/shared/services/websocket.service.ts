import { Injectable } from '@angular/core';
import { Subject, Observable } from 'rxjs';
import { webSocket, WebSocketSubject } from 'rxjs/webSocket';
import { environment } from '../../../environments/environment';
import { SuricataEvent, ConnectionStatus } from './api.service';


export interface RealtimeSuricataAlert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  message: string;
  src_ip: string;
  dest_ip: string;
  timestamp: string;
}

export interface RealtimeMetrics {
  cpu_usage: number;
  memory_usage: number;
  network_throughput: number;
  alerts_per_minute: number;
  events_processed: number;
}

export interface RealtimeEvent {
  type: 'alert' | 'metric' | 'status';
  timestamp: string;
  data: any;
}

@Injectable({
  providedIn: 'root'
})
export class WebsocketService {
  private socket$: WebSocketSubject<any> | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 5000;

  // Subjects for real-time Suricata data
  private alertSubject = new Subject<RealtimeSuricataAlert>();
  private metricsSubject = new Subject<RealtimeMetrics>();
  private statusSubject = new Subject<any>();
  private connectionSubject = new Subject<boolean>();
  private raspiVpsConnectionSubject = new Subject<ConnectionStatus>();

  // Observable streams
  public realtimeAlerts$ = this.alertSubject.asObservable();
  public realtimeMetrics$ = this.metricsSubject.asObservable();
  public connectionStatus$ = this.connectionSubject.asObservable();
  public raspiVpsConnection$ = this.raspiVpsConnectionSubject.asObservable();

  constructor() {
    this.connect();
  }

  private connect(): void {
    if (this.socket$) {
      this.socket$.complete();
    }

    try {
      const token = localStorage.getItem('idps_token');
      this.socket$ = webSocket({
        url: token ? `${environment.wsUrl}?token=${encodeURIComponent(token)}` : environment.wsUrl,
        openObserver: {
          next: () => {
            console.log('WebSocket connected to Suricata API');
            this.connectionSubject.next(true);
            this.reconnectAttempts = 0;
          }
        },
        closeObserver: {
          next: () => {
            console.log('WebSocket disconnected from Suricata API');
            this.connectionSubject.next(false);
            this.handleReconnect();
          }
        }
      });

      this.socket$.subscribe({
        next: (message) => this.handleMessage(message),
        error: (error) => {
          console.error('WebSocket error:', error);
          this.connectionSubject.next(false);
          this.handleReconnect();
        }
      });
    } catch (error) {
      console.error('Failed to connect to Suricata WebSocket:', error);
      this.handleReconnect();
    }
  }

  private handleMessage(message: any): void {
    try {
      const event: any = typeof message === 'string' ? JSON.parse(message) : message;

      switch (event.type) {
        case 'alert': {
          // api-gateway broadcasts flat alert objects (no nested 'data' wrapper)
          const alert: RealtimeSuricataAlert = event.data ?? {
            id: event.id,
            severity: event.severity,
            category: event.category,
            message: event.message,
            src_ip: event.src_ip,
            dest_ip: event.dest_ip ?? '',
            timestamp: event.timestamp,
          };
          this.alertSubject.next(alert);
          break;
        }
        case 'metric': {
          const metrics: RealtimeMetrics = event.data ?? event;
          this.metricsSubject.next(metrics);
          break;
        }
        case 'status':
          this.statusSubject.next(event.data ?? event);
          break;
        case 'connection_status':
          const connectionStatus: ConnectionStatus = event.data ?? event;
          this.raspiVpsConnectionSubject.next(connectionStatus);
          break;
        case 'ping':
          // keepalive — no action needed
          break;
        default:
          console.log('Unknown WebSocket event type:', event.type);
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  }

  private handleReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(`Attempting to reconnect to Suricata API... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
      
      setTimeout(() => {
        this.connect();
      }, this.reconnectInterval);
    } else {
      console.error('Max reconnection attempts reached for Suricata API');
    }
  }

  // Manual reconnect
  reconnect(): void {
    this.reconnectAttempts = 0;
    this.connect();
  }

  // Close connection
  disconnect(): void {
    if (this.socket$) {
      this.socket$.complete();
      this.socket$ = null;
    }
  }

  // Get connection status
  isConnected(): boolean {
    return this.socket$ ? this.socket$.closed === false : false;
  }
}
