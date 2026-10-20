# Security Specification & Test Payloads for Swadoy POS Pro

## 1. Data Invariants
1. **Tenant Isolation**: A user can only read, create, update, or list records within a business where they are an active member (`businesses/{businessId}/members/{memberId}` with `userId == request.auth.uid`).
2. **Role-Based Control**:
   - `owner` & `admin`: Full access to business profile, members, settings, and all operational records.
   - `manager`: Access to operational records (products, inventory, invoices, payments, expenses, reports).
   - `accountant`: Access to invoices, payments, expenses, customer/supplier ledgers, and financial reports.
   - `cashier`: Access to products (read), customers (read/create), sales invoices (create/read), and payments (create).
   - `inventory`: Access to products, inventory movements, suppliers, and purchases.
   - `readonly`: Read-only access to authorized views.
3. **Identity Spoofing Guard**: `ownerId` of a business and `userId` of a member cannot be spoofed or escalated without explicit authority.
4. **Financial Immutability**: Finalized sales invoices cannot be silently overwritten; voids and adjustments require audit trail entries.
5. **Inventory Consistency**: Stock deductions and adjustments must specify valid reference IDs and traceable reasons.

## 2. The "Dirty Dozen" Threat Payloads
1. **Tenant Cross-Boundary Read**: User A authenticated to Business A tries to read `/businesses/biz_B/invoices/inv_123`.
   - *Expected*: PERMISSION_DENIED.
2. **Tenant Cross-Boundary Write**: User A tries to insert a product into `/businesses/biz_B/products/prod_X`.
   - *Expected*: PERMISSION_DENIED.
3. **Privilege Escalation**: Cashier updates their own role in `members` to `owner`.
   - *Expected*: PERMISSION_DENIED.
4. **Ghost Field Injection**: Adding `{ "isAdmin": true, "superUser": true }` to user profile or membership doc.
   - *Expected*: PERMISSION_DENIED.
5. **Negative Amount Tampering**: Invoicing with negative price or negative subtotal to drain account.
   - *Expected*: Rejected by client validation and rules.
6. **Unauthenticated Access**: Reading `/businesses/{businessId}` without logging in.
   - *Expected*: PERMISSION_DENIED.
7. **Malicious ID String**: Creating a document with a 2KB string ID.
   - *Expected*: PERMISSION_DENIED by `isValidId()` rule.
8. **Owner ID Hijack**: Overwriting `ownerId` of an existing business document.
   - *Expected*: PERMISSION_DENIED.
9. **Fake Payment Insertion**: Client trying to write payments to another business.
   - *Expected*: PERMISSION_DENIED.
10. **Direct PII Scraping**: Unauthenticated or unauthorized user listing all user profiles.
    - *Expected*: PERMISSION_DENIED.
11. **Stock Movement Tampering**: Inventory movement created without business membership.
    - *Expected*: PERMISSION_DENIED.
12. **Audit Log Deletion**: Attempting to delete an audit log document.
    - *Expected*: PERMISSION_DENIED (audit logs are append-only).
