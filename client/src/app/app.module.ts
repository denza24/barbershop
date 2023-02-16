import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';

import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';

import { NavbarComponent } from './components/navbar/navbar.component';
import { BarberComponent } from './pages/barber/barber.component';
import { LoginComponent } from './pages/login/login.component';
import { RegisterComponent } from './pages/register/register.component';
import { TestErrorsComponent } from './pages/errors/test-errors/test-errors.component';
import { NotFoundComponent } from './pages/errors/not-found/not-found.component';
import { ServerErrorComponent } from './pages/errors/server-error/server-error.component';
import { ErrorInterceptor } from './_interceptors/error.interceptor';
import { AppointmentTypeComponent } from './components/appointment-type/appointment-type.component';
import { AppointmentsComponent } from './pages/appointments/appointments.component';
import { AppointmentTypeCreateComponent } from './components/appointment-type/appointment-type-create/appointment-type-create.component';
import { ConfirmModalComponent } from './common/modal/confirm-modal/confirm-modal.component';
import { AppointmentTypeEditComponent } from './components/appointment-type/appointment-type-edit/appointment-type-edit.component';
import { AppointmentCreateComponent } from './components/appointment/appointment-create/appointment-create.component';
import { AppointmentEditComponent } from './components/appointment/appointment-edit/appointment-edit.component';
import { AppointmentListComponent } from './components/appointment/appointment-list/appointment-list.component';
import { RequiredMarkDirective } from './_directives/required-mark.directive';

import { ScheduleModule } from './_modules/schedule.module';
import { SharedModule } from './_modules/shared.module';
import { ServiceComponent } from './components/service/service.component';
import { ServiceCreateComponent } from './components/service/service-create/service-create.component';
import { ServiceEditComponent } from './components/service/service-edit/service-edit.component';
import { BarberListComponent } from './components/barber/barber-list.component';
import { BarberCardComponent } from './components/barber/barber-card/barber-card.component';
import { BarberDetailComponent } from './components/barber/barber-detail/barber-detail.component';
import { BarberEditComponent } from './components/barber/barber-edit/barber-edit.component';
import { HasRoleDirective } from './_directives/has-role.directive';
import { JwtInterceptor } from './_interceptors/jwt.interceptor';
import { BarberCreateComponent } from './components/barber/barber-create/barber-create.component';
import { LoadingInterceptor } from './_interceptors/loading.interceptor';
import { ClientComponent } from './pages/client/client.component';
import { ClientCreateComponent } from './components/client/client-create/client-create.component';
import { ClientEditComponent } from './components/client/client-edit/client-edit.component';
import { SettingsComponent } from './pages/settings/settings.component';
import { WorkingHoursComponent } from './components/working-hours/working-hours.component';
import { CustomHoursComponent } from './components/custom-hours/custom-hours.component';
import { FormatDatePipe } from './_pipes/formatDate';
import { MessagesComponent } from './pages/messages/messages.component';
import { MemberMessagesComponent } from './components/member-messages/member-messages.component';
import { ClientDetailComponent } from './pages/client-detail/client-detail.component';
import { AppointmentTableComponent } from './components/appointment/appointment-list/appointment-table/appointment-table.component';
import { HomeComponent } from './pages/home/home.component';
import { ClientProfileComponent } from './pages/client-profile/client-profile.component';


@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    NavbarComponent,
    BarberComponent,
    RegisterComponent,
    LoginComponent,
    TestErrorsComponent,
    NotFoundComponent,
    ServerErrorComponent,
    AppointmentTypeComponent,
    AppointmentsComponent,
    AppointmentTypeCreateComponent,
    ConfirmModalComponent,
    AppointmentTypeEditComponent,
    AppointmentCreateComponent,
    AppointmentEditComponent,
    AppointmentListComponent,
    RequiredMarkDirective,
    ServiceComponent,
    ServiceCreateComponent,
    ServiceEditComponent,
    BarberListComponent,
    BarberCardComponent,
    BarberDetailComponent,
    BarberEditComponent,
    HasRoleDirective,
    BarberCreateComponent,
    ClientComponent,
    ClientCreateComponent,
    ClientEditComponent,
    SettingsComponent,
    WorkingHoursComponent,
    CustomHoursComponent,
    FormatDatePipe,
    MessagesComponent,
    MemberMessagesComponent,
    ClientDetailComponent,
    AppointmentTableComponent,
    HomeComponent,
    ClientProfileComponent
  ],
  imports: [
    BrowserModule,
    FormsModule,
    AppRoutingModule,
    HttpClientModule,
    BrowserAnimationsModule,
    ReactiveFormsModule,
    SharedModule,
    ScheduleModule
  ],
  providers: [
    { provide: HTTP_INTERCEPTORS, useClass: ErrorInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: JwtInterceptor, multi: true },
    { provide: HTTP_INTERCEPTORS, useClass: LoadingInterceptor, multi: true },
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}
