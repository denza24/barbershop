namespace API.DTOs
{
    public class BarberDto
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PhoneNumber { get; set; }
        public string Email { get; set; }
        public int Age { get; set; }
        public string Info { get; set; }
        public PhotoDto Photo { get; set; }
        public DateTime DateOfBirth { get; set; }
        public BarberServiceDto[] BarberServices { get; set; }
        public string Username { get; set; }
    }
}