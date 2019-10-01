using System.Linq;
using Penguin.Cms.Security;
using Penguin.DependencyInjection.Abstractions;
using Penguin.Mail.Abstractions.Attributes;
using Penguin.Persistence.Abstractions.Interfaces;
using System;
using System.Collections.Generic;
using Penguin.Mail.Abstractions.Interfaces;
using Penguin.Mail.Abstractions.Extensions;

namespace Penguin.Cms.Web.Security.Services
{
    /// <summary>
    /// This class provides basic CMS methods for managing and interacting with users
    /// </summary>
    public class UserService : IRegisterMostDerived, IEmailHandler
    {
        /// <summary>
        /// An email template repository
        /// </summary>
        protected ISendTemplates EmailTemplateRepository { get; set; }


        /// <summary>
        /// An IRepository implementation for accessing authentication tokens
        /// </summary>
        protected IRepository<AuthenticationToken> AuthenticationTokenRepository { get; set; }

        protected IRepository<User> UserRepository { get; set; }
        /// <summary>
        /// Constructs a new instance of this service
        /// </summary>
        /// <param name="userRepository">A user repository</param>
        /// <param name="emailTemplateRepository">An email template repository</param>
        /// <param name="authenticationTokenRepository">An IRepository implementation for accessing authentication tokens</param>
        public UserService(IRepository<User> userRepository, ISendTemplates emailTemplateRepository, IRepository<AuthenticationToken> authenticationTokenRepository)
        {
            UserRepository = userRepository;
            EmailTemplateRepository = emailTemplateRepository;
            AuthenticationTokenRepository = authenticationTokenRepository;
        }

        /// <summary>
        /// Gets a user using any valid authentication token
        /// </summary>
        /// <param name="token">The token to use to get the user</param>
        /// <returns>A user if a the token is valid, otherwise null</returns>
        public User GetByAuthenticationToken(AuthenticationToken token)
        {
            if (this.AuthenticationTokenRepository.Where(t => t.User == token.User && t.Guid == token.Guid && t.Expiration > DateTime.Now).Any())
            {
                return UserRepository.Where(u => u.Guid == token.User).FirstOrDefault();
            }

            return null;
        }

        /// <summary>
        /// Returns an authentication token that can be used to reset a password. If email templating is bundled, will send out a password reset email
        /// </summary>
        /// <param name="Login">The login for the user to request</param>
        /// <returns>Returns an authentication token that can be used to reset a password.</returns>
        public AuthenticationToken RequestPasswordReset(string Login) => this.RequestPasswordReset(UserRepository.Find(Login), Guid.Empty);


        /// <summary>
        /// Returns an authentication token that can be used to reset a password. If email templating is bundled, will send out a password reset email
        /// </summary>
        /// <param name="targetUser">The login for the user to request</param>
        /// <param name="Token">Parameter only used by email templating system</param>
        /// <returns>Returns an authentication token that can be used to reset a password.</returns>
        [EmailHandler("Request Password Reset")]
        public AuthenticationToken RequestPasswordReset(User targetUser, Guid Token)
        {
            if (targetUser != null)
            {
                string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                char[] stringChars = new char[16];
                Random random = new Random();

                for (int i = 0; i < stringChars.Length; i++)
                {
                    stringChars[i] = chars[random.Next(chars.Length)];
                }

                Token = Guid.NewGuid();

                this.EmailTemplateRepository.TrySendTemplate(new Dictionary<string, object>()
                {
                    [nameof(targetUser)] = targetUser,
                    [nameof(Token)] = Token
                });

                AuthenticationToken token;

                using (AuthenticationTokenRepository.WriteContext())
                {
                    token = new AuthenticationToken()
                    {
                        Expiration = DateTime.Now.AddMinutes(30),
                        User = UserRepository.Find(targetUser._Id).Guid,
                        Guid = Token
                    };

                    this.AuthenticationTokenRepository.AddOrUpdate(token);
                }

                return token;
            }

            return null;
        }

        /// <summary>
        /// If email templating is enabled, Sends the specified email a message containing the login name of any associated user account 
        /// </summary>
        /// <param name="Email">The email to send information to</param>
        public void SendLoginInformation(string Email) => this.SendLoginInformation(UserRepository.FirstOrDefault(u => u.Email == Email));

        /// <summary>
        /// If email templating is enabled, Sends the specified email a message containing the login name of any associated user account 
        /// </summary>
        /// <param name="targetUser">The user to send login information to</param>
        [EmailHandler("Request Login")]
        public void SendLoginInformation(User targetUser)
        {
            if (targetUser != null)
            {
                this.EmailTemplateRepository.GenerateEmailFromTemplate(new Dictionary<string, object>()
                {
                    [nameof(targetUser)] = targetUser
                });
            }
        }
    }
}
