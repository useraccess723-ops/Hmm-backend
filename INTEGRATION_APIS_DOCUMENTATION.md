# StayFlow External Integrations API Documentation

The StayFlow External Integrations API allows authorized external services, such as the external AI Receptionist, mobile concierges, and channel connectors, to securely query hotel information, check live room availability, calculate dynamic pricing, create reservations with idempotency and row-level locking, and retrieve or cancel reservations.

---

## 1. Authentication & Security Architecture

### Authentication Headers
Every request to external integration endpoints (except public health checks) must provide a valid 72-character service key issued via StayFlow:

```http
Authorization: Bearer sf_live_...
```
*Alternatively, the service key may be sent in header `X-Service-Key: sf_live_...` or `X-Integration-Key: sf_live_...`.*

### Security & Multi-Tenancy Principles
- **SHA-256 Storage**: Raw service keys are never stored in the database. Only their SHA-256 hash is recorded.
- **Tenant Context**: Tenant identity is resolved strictly from the authenticated key. External payloads cannot supply or override the hotel/tenant ID.
- **Granular Scopes**: Operations are gated by individual capability scopes:
  - `hotel:read` (or `knowledge:read`): Hotel details, policies, and knowledge base.
  - `rooms:read`: Room configurations, inventories, and date-range availability.
  - `rates:read`: Dynamic pricing calculations and rate plans.
  - `reservations:create`: Concurrency-safe reservation creation.
  - `reservations:read`: Lookup and retrieval of reservations.
  - `reservations:update`: Modification of reservation dates, guest count, and notes.
  - `reservations:cancel`: Cancellation of active reservations.
- **Rate Limiting**: Sliding window rate limiting is enforced per integration (default: 120 req/min).

---

## 2. API Endpoints Reference

### 2.1 Connection & Health Check
- **Endpoint**: `GET /api/integrations/health` (or `/api/integrations/connection/health`)
- **Authentication**: Optional. If called with service key, returns detailed status and capability scopes.
- **Response (200 OK)**:
```json
{
  "status": "ok",
  "authenticated": true,
  "hotel": {
    "id": 1,
    "code": "GMH",
    "name": "Grand Meridian Hotel",
    "status": "Active"
  },
  "integration": {
    "id": 1,
    "status": "connected",
    "is_enabled": true,
    "scopes": ["hotel:read", "rooms:read", "rates:read", "reservations:create", "reservations:read", "reservations:cancel"]
  },
  "capabilities": {
    "hotel_details": true,
    "room_availability": true,
    "room_rates": true,
    "reservations_create": true,
    "reservations_read": true,
    "reservations_cancel": true
  },
  "timestamp": "2026-11-10T08:00:00Z"
}
```

---

### 2.2 Hotel Information & Policies
- **Endpoint**: `GET /api/integrations/hotel/details`
- **Required Scope**: `hotel:read`
- **Response (200 OK)**:
```json
{
  "hotel_id": 1,
  "hotel_code": "GMH",
  "hotel_name": "Grand Meridian Hotel",
  "currency": "INR",
  "property_details": {
    "slug": "grand-meridian",
    "status": "Active",
    "total_operational_rooms": 120,
    "room_types_count": 4,
    "room_types": [
      {
        "id": 1,
        "name": "Deluxe King",
        "max_occupancy": 3,
        "base_price": 4000.0,
        "total_rooms": 40
      }
    ]
  },
  "address": {
    "street": "100 Ocean Boulevard",
    "city": "Chennai",
    "country": "India",
    "timezone": "Asia/Kolkata"
  },
  "contact": {
    "phone": "+91 44 2800 0000",
    "email": "contact@meridian.com"
  },
  "policies": {
    "check_in_time": "14:00",
    "check_out_time": "11:00",
    "currency": "INR",
    "tax_gst_percent": 12.0,
    "cancellation_hours": 24,
    "cancellation_policy": "Free cancellation up to 24 hours before check-in.",
    "no_show_charge": "First night"
  }
}
```

---

### 2.3 Room Availability Check
- **Endpoint**: `GET /api/integrations/rooms/availability`
- **Required Scope**: `rooms:read`
- **Query Parameters**:
  - `check_in` (required, `YYYY-MM-DD`)
  - `check_out` (required, `YYYY-MM-DD`)
  - `adults` (optional, default `1`)
  - `children` (optional, default `0`)
  - `room_type_id` (optional, filter by specific room type ID)
  - `room_type` (optional, filter by name/slug)
- **Response (200 OK)**:
```json
{
  "hotel_id": 1,
  "hotel_name": "Grand Meridian Hotel",
  "check_in": "2026-11-20",
  "check_out": "2026-11-23",
  "nights": 3,
  "guests": {
    "adults": 2,
    "children": 0,
    "total": 2
  },
  "available_room_types": [
    {
      "room_type_id": 1,
      "room_type_name": "Deluxe King",
      "description": "Spacious deluxe room with sea view.",
      "bed_type": "King-size Bed",
      "occupancy_limits": {
        "max_adults": 2,
        "max_children": 1,
        "max_guests": 3
      },
      "suitable_for_guests": true,
      "base_price": 4000.0,
      "total_inventory": 40,
      "available_count": 18,
      "available_rooms_count": 18,
      "is_available": true,
      "amenities": ["High-speed Wi-Fi", "Mini Bar", "Work Desk"]
    }
  ]
}
```

---

### 2.4 Room Pricing & Rates
- **Endpoint**: `GET /api/integrations/rooms/rates`
- **Required Scope**: `rates:read`
- **Query Parameters**:
  - `check_in` (required, `YYYY-MM-DD`)
  - `check_out` (required, `YYYY-MM-DD`)
  - `room_type_id` (optional, filter by specific room type ID)
  - `adults` (optional, default `1`)
  - `children` (optional, default `0`)
- **Response (200 OK)**:
```json
{
  "hotel_id": 1,
  "hotel_name": "Grand Meridian Hotel",
  "currency": "INR",
  "check_in": "2026-11-20",
  "check_out": "2026-11-22",
  "nights": 2,
  "guests": {
    "adults": 2,
    "children": 1
  },
  "base_price_per_night": 4000.0,
  "total_estimated_price": 9968.0,
  "tax_amount": 1068.0,
  "rates": [
    {
      "room_type_id": 1,
      "room_type_name": "Deluxe King",
      "bed_type": "King-size Bed",
      "pricing": {
        "nights": 2,
        "base_nightly_rate": 4000.0,
        "weekend_nightly_rate": 4500.0,
        "base_subtotal": 8500.0,
        "extra_guest_charges": 400.0,
        "taxable_amount": 8900.0,
        "tax_percent": 12.0,
        "tax_amount": 1068.0,
        "discounts": 0.0,
        "total_estimated_price": 9968.0,
        "currency": "INR"
      },
      "inventory": {
        "available_rooms": 18,
        "is_available": true
      }
    }
  ]
}
```

---

### 2.5 Reservation Creation
- **Endpoint**: `POST /api/integrations/reservations`
- **Required Scope**: `reservations:create`
- **Headers**:
  - `Idempotency-Key` (strongly recommended, unique string per reservation attempt)
- **Request Body (JSON)**:
```json
{
  "room_type_id": 1,
  "check_in": "2026-11-20",
  "check_out": "2026-11-22",
  "adults": 2,
  "children": 0,
  "guest_name": "Koushik Balaji",
  "guest_email": "koushik@example.com",
  "guest_phone": "+919876543210",
  "special_requests": "Quiet room on high floor",
  "payment_method": "Pay At Hotel"
}
```
- **Response (201 Created)**:
```json
{
  "id": 105,
  "reservation_id": 105,
  "booking_reference": "BK-EXT-1-8C4F",
  "status": "Confirmed",
  "allocated_room_number": "102",
  "hotel": {
    "id": 1,
    "name": "Grand Meridian Hotel"
  },
  "guest": {
    "id": 42,
    "name": "Koushik Balaji",
    "phone": "+919876543210",
    "email": "koushik@example.com"
  },
  "room": {
    "id": 5,
    "number": "102",
    "floor": 1,
    "room_type_id": 1,
    "room_type_name": "Deluxe King"
  },
  "dates": {
    "check_in": "2026-11-20",
    "check_out": "2026-11-22",
    "nights": 2
  },
  "pricing": {
    "base_amount": 8500.0,
    "extra_charges": 0.0,
    "subtotal": 8500.0,
    "tax_percent": 12.0,
    "tax_amount": 1020.0,
    "total_amount": 9520.0,
    "currency": "INR"
  },
  "payment_preference": "Pay At Hotel",
  "created_at": "2026-11-10T08:15:30Z"
}
```

---

### 2.6 Retrieve Reservation Details
- **Endpoint**: `GET /api/integrations/reservations/{reservation_id}`
- **Required Scope**: `reservations:read`
- *Parameter `reservation_id` supports either the numeric database ID (`105`) or the booking reference string (`BK-EXT-1-8C4F`).*
- **Response (200 OK)**:
```json
{
  "id": 105,
  "reservation_id": 105,
  "booking_reference": "BK-EXT-1-8C4F",
  "status": "Confirmed",
  "source": "External Integration",
  "hotel": {
    "id": 1,
    "name": "Grand Meridian Hotel",
    "code": "GMH"
  },
  "guest": {
    "id": 42,
    "name": "Koushik Balaji",
    "phone": "+919876543210",
    "email": "koushik@example.com"
  },
  "room": {
    "id": 5,
    "number": "102",
    "floor": 1,
    "room_type_name": "Deluxe King"
  },
  "dates": {
    "check_in": "2026-11-20",
    "check_out": "2026-11-22",
    "nights": 2
  },
  "pricing": {
    "total_amount": 9520.0,
    "currency": "INR"
  }
}
```

---

### 2.7 Modify Reservation
- **Endpoint**: `PATCH /api/integrations/reservations/{reservation_id}` (also supports `PUT`)
- **Required Scope**: `reservations:update`
- **Request Body (JSON)**:
```json
{
  "adults": 2,
  "special_requests": "Late arrival at 6:00 PM"
}
```
- **Response (200 OK)**:
```json
{
  "id": 105,
  "reservation_id": 105,
  "booking_reference": "BK-EXT-1-8C4F",
  "status": "Confirmed",
  "special_requests": "Late arrival at 6:00 PM",
  "message": "Reservation updated successfully."
}
```

---

### 2.8 Cancel Reservation
- **Endpoint**: `POST /api/integrations/reservations/{reservation_id}/cancel` (also supports `DELETE`)
- **Required Scope**: `reservations:cancel`
- **Request Body (JSON)**:
```json
{
  "cancellation_reason": "Guest schedule change"
}
```
- **Response (200 OK)**:
```json
{
  "id": 105,
  "reservation_id": 105,
  "booking_reference": "BK-EXT-1-8C4F",
  "status": "Cancelled",
  "cancellation_reason": "Guest schedule change",
  "cancelled_at": "2026-11-10T08:30:00Z",
  "cancellation_policy": {
    "cancellation_notice_hours": 24,
    "fee_policy": "First night"
  },
  "message": "Reservation cancelled successfully."
}
```

