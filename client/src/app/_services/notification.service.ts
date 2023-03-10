import { Injectable, OnDestroy } from '@angular/core';
import { HubConnection, HubConnectionBuilder } from '@microsoft/signalr';
import { BehaviorSubject } from 'rxjs';
import { environment } from 'src/environments/environment';
import { User } from '../models/user';

@Injectable({
  providedIn: 'root',
})
export class NotificationService implements OnDestroy {
  hubUrl = environment.hubUrl;
  private hubConnection: HubConnection;
  private numberOfUnreadMessagesSource = new BehaviorSubject<number>(0);
  numberOfUnreadMessages$ = this.numberOfUnreadMessagesSource.asObservable();
  private numberOfPendingAppointmentsSource = new BehaviorSubject<number>(0);
  numberOfPendingAppointments$ =
    this.numberOfPendingAppointmentsSource.asObservable();

  constructor() {}

  createHubConnection(user: User) {
    this.hubConnection = new HubConnectionBuilder()
      .withUrl(this.hubUrl + 'notification', {
        accessTokenFactory: () => user.token,
      })
      .withAutomaticReconnect()
      .build();

    this.hubConnection.start().catch((error) => console.log(error));

    this.hubConnection.on('UnreadMessages', (numberOfUnreadMessages) => {
      this.numberOfUnreadMessagesSource.next(numberOfUnreadMessages);

      this.hubConnection.on('NewMessageReceived', (numberOfUnreadMessages) => {
        this.numberOfUnreadMessagesSource.next(numberOfUnreadMessages);
      });
    });

    this.hubConnection.on(
      'PendingAppointments',
      (numberOfPendingAppointments) => {
        this.numberOfPendingAppointmentsSource.next(
          numberOfPendingAppointments
        );
        this.hubConnection.on('NewPendingAppointment', () => {
          this.numberOfPendingAppointmentsSource.next(
            this.numberOfPendingAppointmentsSource.getValue() + 1
          );
        });

        this.hubConnection.on('PendingAppointmentLess', () => {
          this.numberOfPendingAppointmentsSource.next(
            this.numberOfPendingAppointmentsSource.getValue() - 1
          );
        });
      }
    );
  }

  stopHubConnection() {
    if (this.hubConnection) {
      this.hubConnection.stop().catch((error) => console.log(error));
    }
  }

  ngOnDestroy(): void {
    this.stopHubConnection();
  }
}
