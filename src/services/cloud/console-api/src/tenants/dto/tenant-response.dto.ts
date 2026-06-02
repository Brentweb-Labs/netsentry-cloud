export class TenantResponseDto {
  id: string;
  name: string;
  plan: string;
  status: string;
  contactEmail?: string;
  site_count?: number;
  user_count?: number;
  admin_email?: string;
  created_at: string;
  updated_at?: string;

  static fromDocument(doc: any): TenantResponseDto {
    const plain = doc?.toObject?.() || doc || {};
    return {
      id: plain._id?.toString?.() || plain.id,
      name: plain.name,
      plan: plain.plan,
      status: plain.status,
      contactEmail: plain.contactEmail,
      site_count: plain.site_count,
      user_count: plain.user_count,
      admin_email: plain.admin_email,
      created_at: plain.createdAt || plain.created_at,
      updated_at: plain.updatedAt || plain.updated_at,
    };
  }

  static fromDocuments(docs: any[]): TenantResponseDto[] {
    return docs.map(doc => this.fromDocument(doc));
  }
}
