import {
  Component,
  EventEmitter,
  Input,
  OnChanges,
  OnInit,
  Output,
  SimpleChanges,
} from '@angular/core';
import { BsModalRef, BsModalService } from 'ngx-bootstrap/modal';
import { ToastrService } from 'ngx-toastr';
import { take } from 'rxjs';
import { ConfirmModalComponent } from 'src/app/common/modal/confirm-modal/confirm-modal.component';
import { Appointment } from 'src/app/models/appointment';
import { AppointmentStatus } from 'src/app/models/appointmentStatus';
import { User } from 'src/app/models/user';
import { AccountService } from 'src/app/_services/account.service';
import { AppointmentStatusService } from 'src/app/_services/appointment-status.service';
import { AppointmentService } from 'src/app/_services/appointment.service';
@Component({
  selector: 'app-appointment-list',
  templateUrl: './appointment-list.component.html',
  styleUrls: ['./appointment-list.component.css'],
  providers: [BsModalRef, BsModalService],
})
export class AppointmentListComponent implements OnInit, OnChanges {
  @Input() appointments: Appointment[];
  @Output() getAppointments = new EventEmitter();
  @Output() openEditModal = new EventEmitter();

  scheduledCount: number;
  pendingCount: number;
  canceledCount: number;
  completedCount: number;

  appointmentStatuses: AppointmentStatus[];
  deleteModalRef: BsModalRef;
  currentUser: User;

  constructor(
    private appointmentService: AppointmentService,
    private apptStatusService: AppointmentStatusService,
    private toastr: ToastrService,
    private modalService: BsModalService,
    private accountService: AccountService
  ) {}

  ngOnInit(): void {
    this.loadAppointmentStatuses();
    this.accountService.currentUser$.pipe(take(1)).subscribe((user) => {
      this.currentUser = user;
    });
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (
      changes.appointments?.currentValue &&
      changes.appointments?.currentValue !== changes.appointment?.previousValue
    ) {
      this.calculateAppointmentCounts(changes.appointments?.currentValue);
    }
  }

  loadAppointmentStatuses() {
    this.apptStatusService.get().subscribe((data) => {
      this.appointmentStatuses = data;
    });
  }

  onComplete(id: number) {
    this.appointmentService.complete(id).subscribe(() => {
      this.toastr.success('Appointment has been completed');
      this.getAppointments.emit();
    });
  }

  onEdit(appt: Appointment) {
    this.openEditModal.emit(appt);
  }

  onCancel(id: number) {
    this.deleteModalRef = this.modalService.show(ConfirmModalComponent, {
      class: 'modal-dialog-centered',
      initialState: {
        question: 'Are you sure you want to cancel the appointment?',
      },
    });
    this.deleteModalRef.onHide.subscribe(() => {
      if (this.deleteModalRef.content?.message === 'confirmed') {
        this.cancelAppointment(id);
      }
    });
  }

  cancelAppointment(id: number) {
    const isClient = this.currentUser.role === 'Client';

    this.appointmentService.cancel(id, isClient).subscribe(() => {
      this.toastr.info('Appointment has been canceled');
      this.getAppointments.emit();
    });
  }

  calculateAppointmentCounts(appointments: Appointment[]) {
    this.scheduledCount = appointments.filter(
      (appt) => appt.appointmentStatus.name === 'Scheduled'
    ).length;
    this.pendingCount = appointments.filter(
      (appt) => appt.appointmentStatus.name === 'Pending'
    ).length;
    this.canceledCount = appointments.filter(
      (appt) => appt.appointmentStatus.name === 'Canceled'
    ).length;
    this.completedCount = appointments.filter(
      (appt) => appt.appointmentStatus.name === 'Completed'
    ).length;
  }

  onSchedule(id: number) {
    this.appointmentService.schedule(id).subscribe(() => {
      this.toastr.success('Appointment has been scheduled');
      this.getAppointments.emit();
    });
  }
}
