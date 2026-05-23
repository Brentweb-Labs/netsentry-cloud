import { Component, inject, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

interface WireGuardConfig {
  privateKey: string;
  publicKey: string;
  vpsPublicKey: string;
  vpsEndpoint: string;
  localIp: string;
}

interface NetworkConfig {
  wanInterface: string;
  lanInterface: string;
  lanSubnet: string;
  dhcpStart: string;
  dhcpEnd: string;
}

interface SensorSettings {
  suricataEnabled: boolean;
  packetCaptureEnabled: boolean;
  autoBlockEnabled: boolean;
  blockDurationHours: number;
  telemetryEnabled: boolean;
}

@Component({
  selector: 'app-sensor-config',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './sensor-config.html',
  styles: ``,
})
export class SensorConfig implements OnInit {
  activeTab: 'wireguard' | 'network' | 'services' | 'docker' | 'setup' = 'wireguard';

  // WireGuard Config
  wireguardConfig = signal<WireGuardConfig>({
    privateKey: '',
    publicKey: '',
    vpsPublicKey: '',
    vpsEndpoint: 'https://idps.brentweb.eu',
    localIp: '10.10.0.2',
  });
  generatedKeys = signal(false);
  wgCommand = signal('');

  // Network Config
  networkConfig = signal<NetworkConfig>({
    wanInterface: 'eth0',
    lanInterface: 'eth1',
    lanSubnet: '192.168.100.0/24',
    dhcpStart: '192.168.100.100',
    dhcpEnd: '192.168.100.200',
  });

  // Sensor Settings
  sensorSettings = signal<SensorSettings>({
    suricataEnabled: true,
    packetCaptureEnabled: false,
    autoBlockEnabled: false,
    blockDurationHours: 24,
    telemetryEnabled: true,
  });

  // Steps for manual setup
  setupSteps = signal([
    { id: 1, title: 'Generate WireGuard Keys', description: 'Create VPN tunnel keys', completed: false },
    { id: 2, title: 'Configure Network Bridge', description: 'Set up eth0 ↔ eth1 bridge', completed: false },
    { id: 3, title: 'Install Docker Services', description: 'Start NetSentry containers', completed: false },
    { id: 4, title: 'Verify Connection', description: 'Check cloud connectivity', completed: false },
  ]);

  ngOnInit() {
    this.generateWireGuardKeys();
  }

  generateWireGuardKeys() {
    // Simulated key generation - in production these would be generated server-side
    const privateKey = 'YJ0iQVj5qvPGXK3zYhVH3JmRwLx6Pk8nN2vT9aS5mW4=';
    const publicKey = '9xQr4Tk7PnHMmL8vK1cR2NyW5jP0Au9zQ6oBsH3EVDdF8=';

    this.wireguardConfig.update(c => ({
      ...c,
      privateKey,
      publicKey,
    }));
    this.generatedKeys.set(true);

    // Generate the command to add peer on VPS
    this.wgCommand.set(`sudo wg set wg0 peer ${publicKey} allowed-ips 10.10.0.2/32 persistent-keepalive 25`);
  }

  updateVpsEndpoint(endpoint: string) {
    this.wireguardConfig.update(c => ({ ...c, vpsEndpoint: endpoint }));
  }

  toggleSuricata() {
    this.sensorSettings.update(s => ({ ...s, suricataEnabled: !s.suricataEnabled }));
  }

  togglePacketCapture() {
    this.sensorSettings.update(s => ({ ...s, packetCaptureEnabled: !s.packetCaptureEnabled }));
  }

  toggleAutoBlock() {
    this.sensorSettings.update(s => ({ ...s, autoBlockEnabled: !s.autoBlockEnabled }));
  }

  toggleTelemetry() {
    this.sensorSettings.update(s => ({ ...s, telemetryEnabled: !s.telemetryEnabled }));
  }

  markStepComplete(stepId: number) {
    this.setupSteps.update(steps =>
      steps.map(s => s.id === stepId ? { ...s, completed: true } : s)
    );
  }

  get completedSteps(): number {
    return this.setupSteps().filter(s => s.completed).length;
  }
}
