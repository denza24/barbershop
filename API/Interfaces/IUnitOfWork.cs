namespace API.Interfaces
{
    public interface IUnitOfWork
    {
        IMessageRepository MessageRepository {get;}
        IUserRepository UserRepository{get;}
        Task<bool> Complete();
        bool HasChanges();
    }
}