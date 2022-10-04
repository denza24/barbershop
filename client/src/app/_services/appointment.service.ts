import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { environment } from 'src/environments/environment';
import { Appointment } from '../models/appointment';

@Injectable({
  providedIn: 'root',
})
export class AppointmentService {
  baseUrl = environment.apiUrl + 'appointments';
  constructor(private http: HttpClient) {}

  post(resource) {
    return this.http.post(this.baseUrl, resource);
  }

  get() {
    return this.http.get<Appointment[]>(this.baseUrl);
  }

  getById(id: number) {
    return this.http.get<Appointment>(this.baseUrl + '/' + id);
  }

  update(resource) {
    return this.http.put(this.baseUrl + '/' + resource.id, resource);
  }
}
