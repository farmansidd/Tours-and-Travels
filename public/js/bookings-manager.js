/**
 * Treker Tours - Centralized Booking Management
 * This script handles bookings across all destination pages without requiring server changes
 */

// Initialize bookings in localStorage if it doesn't exist
if (!localStorage.getItem('trekerBookings')) {
    localStorage.setItem('trekerBookings', JSON.stringify([]));
}

/**
 * Handle the booking submission
 * @param {Event} event - The form submission event
 * @param {string} destination - The destination being booked
 */
function handleBookingSubmission(event) {
    event.preventDefault();
    
    // Get form elements
    const form = event.target;
    const formData = {
        id: generateBookingId(),
        username: form.querySelector('[name="user_name"]') ? form.querySelector('[name="user_name"]').value : form.querySelector('[name="username"]').value,
        email: form.querySelector('[name="email"]').value,
        phone: form.querySelector('[name="mobile_number"]') ? form.querySelector('[name="mobile_number"]').value : form.querySelector('[name="phone"]').value,
        travelers: form.querySelector('.prod_qty') ? form.querySelector('.prod_qty').value : "1",
        date: form.querySelector('[name="travel_date"]') ? form.querySelector('[name="travel_date"]').value : form.querySelector('[name="time"]').value,
        destination: form.querySelector('[name="destination"]') ? form.querySelector('[name="destination"]').value : getDestinationFromTitle(),
        tourType: form.querySelector('[name="tour-type"]') ? form.querySelector('[name="tour-type"]').value : "Standard Tour",
        bookingDate: new Date().toISOString(),
        status: 'Pending'
    };

    // Save to localStorage
    saveBooking(formData);
    
    // Show success message
    alert('Booking successful! Reference ID: ' + formData.id);
    
    // Reset the form
    form.reset();
}

/**
 * Safely get destination from document title
 * @returns {string} - The destination name
 */
function getDestinationFromTitle() {
    try {
        const titleParts = document.title.split('-');
        return titleParts.length > 1 ? titleParts[1].trim() : "Unknown Destination";
    } catch (error) {
        console.log('Error extracting destination from title:', error);
        return "Unknown Destination";
    }
}

/**
 * Generate a unique booking ID
 * @returns {string} - A unique booking ID
 */
function generateBookingId() {
    return 'TRK-' + Date.now().toString().slice(-6) + '-' + Math.floor(Math.random() * 1000);
}

/**
 * Save a booking to localStorage
 * @param {Object} bookingData - The booking data to save
 */
function saveBooking(bookingData) {
    // Get existing bookings
    const bookings = JSON.parse(localStorage.getItem('trekerBookings')) || [];
    
    // Add the new booking
    bookings.push(bookingData);
    
    // Save back to localStorage
    localStorage.setItem('trekerBookings', JSON.stringify(bookings));
    
    console.log('Booking saved:', bookingData);
}

/**
 * Get all bookings from localStorage
 * @returns {Array} - Array of booking objects
 */
function getAllBookings() {
    return JSON.parse(localStorage.getItem('trekerBookings')) || [];
}

/**
 * Update a booking's status
 * @param {string} bookingId - The ID of the booking to update
 * @param {string} newStatus - The new status ('Confirmed', 'Cancelled', 'Completed')
 */
function updateBookingStatus(bookingId, newStatus) {
    const bookings = getAllBookings();
    const bookingIndex = bookings.findIndex(booking => booking.id === bookingId);
    
    if (bookingIndex !== -1) {
        bookings[bookingIndex].status = newStatus;
        localStorage.setItem('trekerBookings', JSON.stringify(bookings));
        return true;
    }
    
    return false;
}

/**
 * Delete a booking
 * @param {string} bookingId - The ID of the booking to delete
 */
function deleteBooking(bookingId) {
    const bookings = getAllBookings();
    const updatedBookings = bookings.filter(booking => booking.id !== bookingId);
    
    localStorage.setItem('trekerBookings', JSON.stringify(updatedBookings));
}

// Attach the submit handler to all booking forms when the page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log('Booking manager initialized');
    
    const bookingForm = document.getElementById('bookingForm');
    if (bookingForm) {
        console.log('Booking form found, attaching handler');
        bookingForm.addEventListener('submit', handleBookingSubmission);
    } else {
        console.log('No booking form found on this page');
        
        // Try to find other booking forms
        const contactForms = document.querySelectorAll('form[action="sendemail.php"]');
        contactForms.forEach(form => {
            console.log('Found a contact form, attaching handler');
            form.addEventListener('submit', handleBookingSubmission);
        });
    }
}); 