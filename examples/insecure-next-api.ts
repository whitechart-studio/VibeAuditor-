export async function POST(request: Request) {
  const body = await request.json();
  const prompt = `Summarize this customer request: ${body.message}`;

  await supabase.from("orders").insert({
    user_id: body.userId,
    total: body.total,
  });

  return Response.json({ prompt });
}
