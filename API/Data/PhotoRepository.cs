using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.EntityFrameworkCore;

namespace API.Data
{
    public class PhotoRepository : IPhotoRepository
    {
        private readonly DataContext _context;
        public PhotoRepository(DataContext context)
        {
            _context = context;
            
        }
        public async Task<IEnumerable<PhotoForApprovalDto>> GetUnapprovedPhotos ()
        {
            return await _context.Photos
                 .IgnoreQueryFilters()
                 .Where(p => p.IsApproved == false)
                 .Select( u => new PhotoForApprovalDto
                 {
                        Id = u.Id,
                        Url = u.Url,
                        Username = u.AppUser.UserName,
                        IsApproved = u.IsApproved
                 }).ToListAsync();
            
        }

        public async Task<Photo> GetPhotoById(int id)
        {
            return await _context.Photos
                .IgnoreQueryFilters()
                .FirstOrDefaultAsync(p => p.Id == id);
        }

        public void RemovePhoto(Photo photo)
        {
            _context.Photos.Remove(photo);
        }
    }
}