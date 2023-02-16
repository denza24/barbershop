import { Photo } from './photo';

export class User {
  id: number;
  username: string;
  dateOfBirth: Date;
  token: string;
  role: string;
  firstName: string;
  lastName: string;
  fullName: string;
  email: string;
  phoneNumber: string;
  photo?: Photo;
  clientId?: number;
  barberId?: number;
}

export class Address {
  firstName: string;
  lastName: string;
  street: string;
  city: string;
  zipCode: string;
  country: string;
}