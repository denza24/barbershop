namespace API.Entities
{
    public class Client
    {
        public int Id { get; set; }
        public int AppUserId { get; set; }
        public AppUser AppUser { get; set; }
        public bool SmsNotification { get; set; }
        public bool EmailNotification { get; set; }
    }
}