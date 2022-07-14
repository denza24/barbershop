import { Location } from '@angular/common';
import { Component, OnInit } from '@angular/core';
import { Appointment } from 'src/app/models/appointment';
import { AppointmentType } from 'src/app/models/appointmentType';
import { Barber } from 'src/app/models/barber';
import { Client } from 'src/app/models/client';
import { AppointmentTypeService } from 'src/app/_services/appointment-type.service';
import { BarberService } from 'src/app/_services/barber.service';
import { ClientService } from 'src/app/_services/client.service';

@Component({
  selector: 'app-appointment-create',
  templateUrl: './appointment-create.component.html',
  styleUrls: ['./appointment-create.component.css'],
})
export class AppointmentCreateComponent implements OnInit {
  model: Appointment = {
    startsAt: new Date(new Date().setHours(0, 0, 0, 0)),
    duration: 0,
    id: 0,
    endsAt: new Date(new Date().setHours(0, 0, 0, 0)),
    appointmentTypeId: 0,
    barberId: 0,
    clientId: 0,
    appointmentType: undefined,
    client: undefined,
    barber: undefined,
  };

  appointmentTypes: AppointmentType[];
  barbers: Barber[];
  clients: Client[];

  selectedApptType: any;
  selectedBarber: any;
  selectedClient: any;

  constructor(
    private appointmentTypeService: AppointmentTypeService,
    private barberService: BarberService,
    private clientService: ClientService,
    private location: Location
  ) {}

  ngOnInit(): void {
    this.loadAppointmentTypes();
    this.loadClients();
    this.loadBarbers();
  }

  insertAppointment() {
    console.log(this.model);
  }

  setAppointmentDuration() {
    this.model.duration = this.appointmentTypes.find(
      (at) => at.id === this.selectedApptType
    ).duration;

    this.updateEndTime();
  }

  updateEndTime() {
    var date = new Date(this.model.startsAt);
    date.setMinutes(this.model.startsAt.getMinutes() + this.model.duration);
    this.model.endsAt = date;
  }

  getSelectedTypeColor(): string {
    return this.appointmentTypes?.find((at) => at.id === this.selectedApptType)
      .color;
  }

  loadBarbers() {
    this.barberService.getBarbers().subscribe((data: Barber[]) => {
      this.barbers = data;
    });
  }

  loadClients() {
    this.clientService.getClients().subscribe((data) => {
      this.clients = data;
    });
  }

  loadAppointmentTypes() {
    this.appointmentTypeService.getAppointmentTypes().subscribe((data) => {
      this.appointmentTypes = data;
    });
  }

  cancel() {
    this.location.back();
  }
}
