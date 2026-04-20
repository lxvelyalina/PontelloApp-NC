using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.VisualStudio.Web.CodeGenerators.Mvc.Templates.BlazorIdentity.Pages.Manage;
using PontelloApp.Custom_Controllers;
using PontelloApp.Models;
using PontelloApp.ViewModels;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace PontelloApp.Controllers
{
    public class AccountController : ElephantController
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _emailSender;

        public AccountController(SignInManager<User> signInManager, UserManager<User> userManager, RoleManager<IdentityRole> roleManager, IEmailSender emailSender)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _emailSender = emailSender;
        }

        //  Auth 

        public IActionResult Login() => View();

        [HttpPost]
        public async Task<IActionResult> Login(LoginVM model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Email or password is incorrect.");
                return View(model);
            }

            if (user.Status == AccountStatus.Pending)
            {
                ModelState.AddModelError("", "Your account is pending admin approval.");
                return View(model);
            }

            if (user.Status == AccountStatus.Inactive)
            {
                ModelState.AddModelError("", "Your account has been deactivated.");
                return View(model);
            }

            var result = await _signInManager.PasswordSignInAsync(user.UserName, model.Password, model.RememberMe, false);
            if (result.Succeeded)
            {
                var roles = await _userManager.GetRolesAsync(user);

                if (roles.Contains("Admin"))
                {
                    return RedirectToAction("Index", "Product"); 
                }
                else
                {
                    return RedirectToAction("Index", "ProductDealer");
                }
            }    

            ModelState.AddModelError("", "Email or password is incorrect.");
            return View(model);
        }

      public IActionResult Register()
        {
            var model = new RegisterVM();
            return View(model);
        }
        
        [HttpPost]
        public async Task<IActionResult> Register(RegisterVM model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = new User
            {
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.Phone,
                Email = model.Email,
                UserName = model.Email,
                BINorEIN = model.BINorEIN,
                // Company
                CompanyName = model.CompanyName,
                // Address
                AddressLine1 = model.AddressLine1,
                AddressLine2 = model.AddressLine2,
                City = model.City,
                Province = model.Province,
                PostalCode = model.PostalCode,
                Country = model.Country,
                // Status
                Status = AccountStatus.Pending
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Dealer");
                TempData["Message"] = "Registration successful. Your account is pending admin approval.";
                return RedirectToAction("Login");
            }

            foreach (var error in result.Errors)
                ModelState.AddModelError(string.Empty, error.Description);

            return View(model);
        }

        public IActionResult VerifyEmail() => View();

        [HttpPost]
        public async Task<IActionResult> VerifyEmail(VerifyEmailVM model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "No account found.");
                return View(model);
            }

            // Generate token
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var encodedToken = System.Net.WebUtility.UrlEncode(token);

            // Redirect
            var link = Url.Action("ChangePassword", "Account", new
            {
                email = user.Email,
                token = encodedToken
            }, Request.Scheme);

            var message = $@"
            <div style='font-family: Arial, sans-serif; background-color:#f4f4f4; padding:20px;'>
                <div style='max-width:600px; margin:0 auto; background:#ffffff; border-radius:10px; overflow:hidden; border:1px solid #ddd;'>

                    <div style='background:#198754; color:white; padding:20px; text-align:center;'>
                        <h2 style='margin:0;'>Password Reset Request</h2>
                    </div>

                    <div style='padding:30px; color:#333; font-size:15px; line-height:1.6;'>

                        <p>Hi,</p>

                        <p>We received a request to reset your password.</p>

                        <p style='margin-top:20px;'>
                            Click the button below to reset your password:
                        </p>

                        <div style='text-align:center; margin:30px 0;'>
                            <a href='{link}' 
                               style='background:#198754; color:white; padding:12px 25px; text-decoration:none; border-radius:6px; display:inline-block; font-weight:bold;'>
                                Reset Password
                            </a>
                        </div>

                        <p style='color:#777; font-size:13px;'>
                            If you didn’t request this, you can safely ignore this email.
                        </p>

                    </div>

                    <div style='background:#f1f1f1; padding:15px; text-align:center; font-size:12px; color:#888;'>
                        © PontelloApp - All rights reserved
                    </div>

                </div>
            </div>";

            await _emailSender.SendEmailAsync(user.Email, "Reset Password", message);

            TempData["SuccessMessage"] = "Check your email to reset password.";
            return View();
        }

        public IActionResult ChangePassword(string email, string token)
        {
            if (email == null || token == null)
                return RedirectToAction("VerifyEmail");

            return View(new ChangePasswordVM
            {
                Email = email,
                Token = token
            });
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePasswordVM model)
        {
            if (!ModelState.IsValid) return View(model);

            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "User not found.");
                return View(model);
            }

            var decodedToken = System.Net.WebUtility.UrlDecode(model.Token);

            var result = await _userManager.ResetPasswordAsync(
                user,
                decodedToken,
                model.NewPassword
            );

            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = "Password changed successfully!";
                return RedirectToAction("Login");
            }
            else
            {
                foreach (var e in result.Errors)
                    ModelState.AddModelError("", e.Description);

                return View(model);
            }    
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Login", "Account");
        }

        //  Profile / Settings 

        [Authorize]
        public IActionResult Profile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = _userManager.FindByIdAsync(userId).Result;
            if (user == null) return NotFound();
            return View(user);
        }

        [Authorize]
        public IActionResult Settings()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = _userManager.FindByIdAsync(userId).Result;
            if (user == null) return NotFound();
            return View(user);
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> UpdateProfile(
            string FirstName, string LastName, string Email, string PhoneNumber,
            string CompanyName, string BINorEIN,
            string AddressLine1, string AddressLine2,
            string City, string Province, string PostalCode, string Country)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            user.FirstName = FirstName;
            user.LastName = LastName;
            user.Email = Email;
            user.UserName = Email;
            user.PhoneNumber = PhoneNumber;
            user.CompanyName = CompanyName;
            user.BINorEIN = BINorEIN;
            user.AddressLine1 = AddressLine1;
            user.AddressLine2 = AddressLine2;
            user.City = City;
            user.Province = Province;
            user.PostalCode = PostalCode;
            user.Country = Country;

            var result = await _userManager.UpdateAsync(user);
            if (result.Succeeded)
                TempData["SuccessMessage"] = "Profile updated successfully.";
            else
                TempData["ErrorMessage"] = "Update failed.";
            return RedirectToAction("Settings");
        }

        [HttpPost]
        [Authorize]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePasswordSettings(string CurrentPassword, string NewPassword, string ConfirmPassword)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return NotFound();

            if (NewPassword != ConfirmPassword)
            {
                TempData["ErrorMessage"] = "New password and confirmation do not match.";
                return RedirectToAction("Settings");
            }

            var result = await _userManager.ChangePasswordAsync(user, CurrentPassword, NewPassword);
            if (result.Succeeded)
            {
                await _signInManager.RefreshSignInAsync(user);
                TempData["SuccessMessage"] = "Password changed successfully.";
            }
            else
            {
                TempData["ErrorMessage"] = string.Join(" ", result.Errors.Select(e => e.Description));
            }

            return RedirectToAction("Settings");
        }

        //  Admin: Accounts list 

        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> Accounts()
        {
            var users = _userManager.Users.ToList();
            var pendingUsers = users.Where(u => u.Status == AccountStatus.Pending).ToList();

            var rolesDict = new Dictionary<string, string>();
            foreach (var u in users)
            {
                var roles = await _userManager.GetRolesAsync(u);
                rolesDict[u.Id] = string.Join(", ", roles);
            }

            ViewBag.UserRoles = rolesDict;
            ViewBag.PendingUsers = pendingUsers;

            return View(users);
        }

        //  Admin: Edit user 

        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> EditUser(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            ViewBag.AllRoles = _roleManager.Roles.Select(r => r.Name).ToList();
            ViewBag.UserRoles = await _userManager.GetRolesAsync(user);

            return View(user);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditUser(
            string id,
            string firstName,
            string lastName,
            string email,
            string phone,
            string binOrEIN,
            List<string> roles)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            // Protect the seed admin's role
            const string seedAdminEmail = "admin@gmail.com";
            if (user.Email == seedAdminEmail && !roles.Contains("Admin"))
            {
                ModelState.AddModelError("", "The seed admin account must always keep the Admin role.");

                ModelState.Remove("BINorEIN");

                ViewBag.AllRoles = _roleManager.Roles.Select(r => r.Name).ToList();
                ViewBag.UserRoles = await _userManager.GetRolesAsync(user);
                return View(user);
            }

            user.FirstName = firstName;
            user.LastName = lastName;
            user.Email = email;
            user.UserName = email; // keep UserName in sync with Email
            user.PhoneNumber = phone;
            user.BINorEIN = binOrEIN;

            var currentRoles = await _userManager.GetRolesAsync(user);
            var toAdd = roles.Except(currentRoles).ToList();
            var toRemove = currentRoles.Except(roles).ToList();

            if (toAdd.Any()) await _userManager.AddToRolesAsync(user, toAdd);
            if (toRemove.Any()) await _userManager.RemoveFromRolesAsync(user, toRemove);

            await _userManager.UpdateAsync(user);

            TempData["Message"] = "User updated successfully.";
            return RedirectToAction("EditUser", new { id = user.Id });
        }

        //  Admin: Status actions 

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApprovePendingConfirmed(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            user.Status = AccountStatus.Active;
            var result = await _userManager.UpdateAsync(user);

            TempData["Message"] = result.Succeeded
                ? $"{user.Email} has been approved and activated."
                : $"Could not approve {user.Email}.";

            return RedirectToAction("Accounts");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RejectPendingConfirmed(string id)
        {
            if (string.IsNullOrEmpty(id)) return NotFound();

            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            user.Status = AccountStatus.Rejected;
            var result = await _userManager.UpdateAsync(user);

            TempData["Message"] = result.Succeeded
                ? $"{user.Email} has been rejected."
                : $"Could not reject {user.Email}.";

            return RedirectToAction("Accounts");
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ToggleActiveInactive(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null) return NotFound();

            if (user.Email == "admin@gmail.com" && user.Status == AccountStatus.Active)
            {
                TempData["ErrorMessage"] = "Cannot deactivate the main admin account.";
                return RedirectToAction("EditUser", new { id });
            }

            user.Status = user.Status == AccountStatus.Active ? AccountStatus.Inactive : AccountStatus.Active;
            var result = await _userManager.UpdateAsync(user);

            if (result.Succeeded)
            {
                TempData["SuccessMessage"] = $"User status updated to {user.Status}.";
            }
            else
            {
                TempData["ErrorMessage"] = "Failed to update user status.";
            }

            return RedirectToAction("EditUser", new { id });
        }
    }
}
